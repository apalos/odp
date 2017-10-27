#include <odp_posix_extensions.h>
#include <stdio.h>
#include <endian.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/types.h>

#include <odp_packet_io_internal.h>
#include <odp/drv/byteorder.h>
#include <odp/api/hints.h>

#include <drivers/r8169.h>
#include <drivers/driver_ops.h>
#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>

#include <uapi/net_mdev.h>

typedef unsigned long dma_addr_t;

/** Packet socket using mediated r8169 device */
typedef struct {
	/* TODO: cache align everything when we have profiling information */
	odp_pktio_capability_t capa;	/**< interface capabilities */

	/* volatile void *mmio; */
	void *mmio;		/**< BAR2 mmap */

	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_ticketlock_t rx_lock;	/**< RX ring lock */
	struct r8169_rxdesc *rx_ring;	/**< RX ring mmap */
	struct iomem rx_data;		/**< RX packet payload mmap */
	uint16_t rx_next;		/**< next entry in RX ring to use */
	// rx_tail, rx_head ? (mmio + offset)

	odp_bool_t lockless_tx;		/**< no locking for TX */
	odp_ticketlock_t tx_lock;	/**< TX ring lock */
	struct r8169_txdesc *tx_ring;	/**< TX ring mmap */
	struct iomem tx_data;		/**< TX packet payload mmap */
	uint16_t tx_next;		/**< next entry in TX ring to use */
	// tx_tail, tx_head ? (mmio + offset)
} pktio_ops_r8169_data_t;

static inline void rtl8169_mark_to_asic(struct r8169_rxdesc *desc, __u32 rx_buf_sz)
{
	__u32 eor = odpdrv_le_to_cpu_32(desc->opts1) & RingEnd;

	/* Force memory writes to complete before releasing descriptor */
	dma_wmb();

	desc->opts1 = odpdrv_cpu_to_le_32(DescOwn | eor | rx_buf_sz);
}

static inline void rtl8169_map_to_asic_rx(struct r8169_rxdesc *desc, dma_addr_t mapping,
					  __u32 rx_buf_sz)
{
	desc->addr = odpdrv_cpu_to_le_64(mapping);
	rtl8169_mark_to_asic(desc, rx_buf_sz);
}

static inline void rtl8169_mark_as_last_descriptor(struct r8169_rxdesc *desc)
{
	desc->opts1 |= odpdrv_cpu_to_le_32(RingEnd);
}

static int r8169_rx_fill(void *rx_data, struct iomem data, char *rx_buff[],
			 volatile void *ioaddr)
{
	unsigned int i;
	struct r8169_rxdesc *r8169_rxring = (struct r8169_rxdesc *) rx_data;

	if (!ioaddr)
		return -1;

	for (i = 0; i < NUM_RX_DESC; i++) {
		rtl8169_map_to_asic_rx(&r8169_rxring[i], data.iova + i * 2048, 2048);
		rx_buff[i] = (char *)(data.vaddr + i * 2048);
	}
	rtl8169_mark_as_last_descriptor(&r8169_rxring[NUM_RX_DESC - 1]);

	return 0;
}

static void r8169_recv(void *rxring, char *rx_buff[] ODP_UNUSED, volatile void *ioaddr)
{
	unsigned int i = 0;
	struct r8169_rxdesc *r8169_rxring = (struct r8169_rxdesc *)rxring;

	if (!ioaddr)
		return;

	while (1) {
		if (i >= NUM_RX_DESC)
			i = 0;
		for (; i < NUM_RX_DESC; i++) {
			__u32 status;

			status = odpdrv_le_to_cpu_32(r8169_rxring[i].opts1) & ~0; /// either  ~(RxBOVF | RxFOVF) or ~0;

			if (status & DescOwn) {
				usleep(100*1000);
				break;
			}
			/* This barrier is needed to keep us from reading
			* any other fields out of the Rx descriptor until
			* we know the status of DescOwn
			*/
			dma_rmb();

			if (odp_unlikely(status & RxRES)) {
				printf("Rx ERROR. status = %08x\n",status);
				if ((status & (RxRUNT | RxCRC)) &&
					!(status & (RxRWT | RxFOVF))
					/* && 	(dev->features & NETIF_F_RXALL) */
					)
					goto process_pkt;
			} else {
				int pkt_size;
process_pkt:
				if (1) // likely(!(dev->features & NETIF_F_RXFCS)))
					pkt_size = (status & 0x00003fff) - 4;
				else
					pkt_size = status & 0x00003fff;

				printf("desc[%03d]: size= %5d ", i, pkt_size);
				printf("\n");
			}
			/* release_descriptor: */
			r8169_rxring[i].opts2 = 0;
			rtl8169_mark_to_asic(&r8169_rxring[i], 2048);
		}
	}
}

static inline void rtl8169_map_to_asic_tx(struct r8169_txdesc *desc, dma_addr_t mapping)

{
	desc->addr = odpdrv_cpu_to_le_64(mapping);
}

static void r8169_xmit(void *txring, struct iomem data, volatile void *ioaddr)
{
	const int idx = 0;
	__u32 opts[2];
	__u32 status, len;
	int entry = 0;
	struct r8169_txdesc *r8169_txring = (struct r8169_txdesc *)txring;
	char *tx_buff ODP_UNUSED = (char *)(data.vaddr + idx * 2048);

	/* XXX FIXME need proper packet size and sizeof(src) *NOT* dst */
	rtl8169_map_to_asic_tx(&r8169_txring[idx], data.iova + idx * 2048);
	/* FIXME no fragmentation support */
	opts[0] = DescOwn;
	opts[0] |= FirstFrag | LastFrag;
	/* FIXME No vlan support */
	opts[1] = odpdrv_cpu_to_le_32(0x00);
	/* FIXME get actual packet size */
	len = 64;

	status = opts[0] | len | (RingEnd * !((entry + 1) % NUM_TX_DESC));
	r8169_txring->opts1 = odpdrv_cpu_to_le_32(status);
	r8169_txring->opts2 = odpdrv_cpu_to_le_32(opts[1]);
	io_write8(NPQ, (volatile char *)ioaddr + TxPoll);

	return;
}

static void r8169_prepare_rx(pktio_entry_t * pktio_entry,
			     uint16_t from, uint16_t num)
{
	pktio_ops_r8169_data_t *pkt_r8169 =
	    odp_ops_data(pktio_entry, r8169);
	struct r8169_rxdesc *r8169_rxring;
	uint16_t i = from;

	while (num && num < NUM_RX_DESC) {
		r8169_rxring = &pkt_r8169->rx_ring[i];
		dma_addr_t dma_addr =
		    pkt_r8169->rx_data.iova + i * R8169_RX_BUF_SIZE;
		rtl8169_map_to_asic_rx(&r8169_rxring[i], dma_addr, R8169_RX_BUF_SIZE);

		i++;
		if (i == NUM_RX_DESC)
			i = 0;
		num--;
	}

	rtl8169_mark_as_last_descriptor(&r8169_rxring[NUM_RX_DESC - 1]);
}

static int r8169_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		      const char *netdev ODP_UNUSED, odp_pool_t pool ODP_UNUSED)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	int container = -1, group = -1, device = -1;
	int ret;
	void *iobase, *iocur;
	pktio_ops_r8169_data_t *pkt_r8169 =
	    odp_ops_data(pktio_entry, r8169);
	size_t rx_len, tx_len, mmio_len;
	struct iomem rx_data, tx_data;
	char group_uuid[64]; /* 37 should be enough */

	/* Init pktio entry */
	memset(pkt_r8169, 0, sizeof(*pkt_r8169));
	memset(group_uuid, 0, sizeof(group_uuid));

	pkt_r8169->capa.max_input_queues = 1;
	pkt_r8169->capa.max_output_queues = 1;

	odp_ticketlock_init(&pkt_r8169->rx_lock);
	odp_ticketlock_init(&pkt_r8169->tx_lock);

	/* FIXME iobase and container(probably) has to be done globally and not per driver */
	iobase = iomem_init();
	if (!iobase)
		return -ENOMEM;
	iocur = iobase;
	container = get_container();
	if (container < 0)
		goto out;

	/* FIXME Get group_id from name */
	group = get_group(11);
	if (group < 0)
		goto out;

	device = vfio_init_dev(group, container, &group_status, &iommu_info,
			       &device_info, group_uuid);

	/* Init device and mmaps */
	pkt_r8169->mmio = vfio_mmap_region(device, 2, &mmio_len);
	if (!pkt_r8169->mmio)
		return -1; /* FIXME map return values to odp errors */

	pkt_r8169->rx_ring = vfio_mmap_region(device, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_RX_REGION_INDEX, &rx_len);
	if (!pkt_r8169->rx_ring) {
		printf("Cannot map RxRing\n");
		goto out;
	}
	pkt_r8169->tx_ring = vfio_mmap_region(device, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_TX_REGION_INDEX, &tx_len);
	if (!pkt_r8169->tx_ring) {
		printf("Cannot map TxRing\n");
		goto out;
	}

	/* TODO: we shall pass only 2 params to iomem_alloc_dma(): fd and iomem
	 * requested size can be in iomem->size.
	 * function will fill in vaddr and iova.
	 */
	/* FIXME decide on allocated areas per hardware instead of getting 2MB
	 * per direction
	 */
	rx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(device, &iocur, &rx_data);
	if (ret)
		goto out;

	tx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(device, &iocur, &tx_data);
	if (ret)
		goto out;

	r8169_prepare_rx(pktio_entry, 0, NUM_RX_DESC);
	// call common code: transition complete

	return 0;

out:
	if (iobase)
		iomem_free(iobase);
	if (pkt_r8169->rx_ring)
		munmap(pkt_r8169->rx_ring, rx_len);
	if (pkt_r8169->tx_ring)
		munmap(pkt_r8169->tx_ring, tx_len);
	if (pkt_r8169->mmio)
		munmap(pkt_r8169->mmio, mmio_len);
	if (group)
		close(group);
	if (container)
		close(container);

	return -1;
}

static int r8169_close(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

/* FIXME make this staic once we have loadbale module support */
const struct driver_ops r8169_ops = {
	.rx_fill = r8169_rx_fill,
	.recv = r8169_recv,
	.xmit = r8169_xmit,
};

static pktio_ops_module_t r8169_pktio_ops ODP_UNUSED = {
	.base = {
		 .name = "r8169",
		 },

	.open = r8169_open,
	.close = r8169_close,

	//.recv = e1000e_recv,
	//.send = e1000e_send,
};
