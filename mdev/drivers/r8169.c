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
#include <odp/drv/hints.h>

#include <drivers/r8169.h>
#include <drivers/driver_ops.h>
#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>
#include <sysfs_parse.h>

#include <uapi/net_mdev.h>

/* Common code. TODO: relocate */
#if 1
typedef unsigned long dma_addr_t;
#endif

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

	odp_bool_t lockless_tx;		/**< no locking for TX */
	odp_ticketlock_t tx_lock;	/**< TX ring lock */
	struct r8169_txdesc *tx_ring;	/**< TX ring mmap */
	struct iomem tx_data;		/**< TX packet payload mmap */
	uint16_t tx_next;		/**< next entry in TX ring to use */
} pktio_ops_r8169_data_t;

static void r8169_rx_refill(pktio_entry_t *pktio_entry,
			    uint16_t from, uint16_t num);

#if 0
static inline void rtl8169_map_to_asic_tx(struct r8169_txdesc *desc, dma_addr_t mapping)

{
	desc->addr = odpdrv_cpu_to_le_64(mapping);
}

static void ODP_UNUSED r8169_xmit(void *txring, struct iomem data,
				  volatile void *ioaddr)
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
#endif

static int r8169_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t * pktio_entry,
		      const char *netdev, odp_pool_t pool ODP_UNUSED)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	int container = -1, group = -1, device = -1;
	int ret = -EINVAL;
	void *iobase, *iocur;
	pktio_ops_r8169_data_t *pkt_r8169 =
	    odp_ops_data(pktio_entry, r8169);
	size_t rx_len, tx_len, mmio_len;
	struct iomem rx_data, tx_data;
	char group_uuid[64]; /* 37 should be enough */
	int group_id;

	printf("r8169: probing %s\n", netdev);

	/* Init pktio entry */
	memset(pkt_r8169, 0, sizeof(*pkt_r8169));
	memset(group_uuid, 0, sizeof(group_uuid));

	group_id = mdev_sysfs_discover(netdev, R8169_MOD_NAME, group_uuid,
				       sizeof(group_uuid));
	if (group_id < 0)
		return -EINVAL;

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
	group = get_group(group_id);
	if (group < 0)
		goto out;

	device = vfio_init_dev(group, container, &group_status, &iommu_info,
			       &device_info, group_uuid);
	if (device < 0)
		goto out;

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

	r8169_rx_refill(pktio_entry, 0, NUM_RX_DESC);

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

static int r8169_close(pktio_entry_t * pktio_entry ODP_UNUSED)
{
	return 0;
}

/* TODO: pass pkt_r8169 */
static void r8169_rx_refill(pktio_entry_t *pktio_entry,
			    uint16_t from, uint16_t num)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	uint16_t i = from;

	ODP_ASSERT(num <= NUM_RX_DESC);

	while (num) {
		struct r8169_rxdesc *rx_desc = &pkt_r8169->rx_ring[i];
		dma_addr_t dma_addr =
		    pkt_r8169->rx_data.iova + i * R8169_RX_BUF_SIZE;
		uint32_t opts1;

		rx_desc->addr = odpdrv_cpu_to_le_64(dma_addr);
		rx_desc->opts2 = odpdrv_cpu_to_le_32(0);

		if (odp_likely(i < NUM_RX_DESC - 1)) {
			opts1 = DescOwn | R8169_RX_BUF_SIZE;
			i++;
		} else {
			opts1 = DescOwn | R8169_RX_BUF_SIZE | RingEnd;
			i = 0;
		}
		num--;

		dma_wmb();
		rx_desc->opts1 = odpdrv_cpu_to_le_32(opts1);
	}
}

static int r8169_recv(pktio_entry_t * pktio_entry, int index ODP_UNUSED,
		      odp_packet_t pkt_table[], int num)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	uint16_t refill_from;
	int rx_pkts = 0;

	/* Keep track of the start point to refill RX ring */
	refill_from = pkt_r8169->rx_next;

	while (rx_pkts < num) {
		struct r8169_rxdesc *rx_desc =
		    &pkt_r8169->rx_ring[pkt_r8169->rx_next];
		odp_packet_hdr_t *pkt_hdr;
		odp_packet_t pkt;
		uint16_t pkt_len;
		uint32_t status;

		status = odpdrv_le_to_cpu_32(rx_desc->opts1);
		if (status & DescOwn)
			break;

		dma_rmb();

		/* FIXME: let the HW drop all erroneous packets */
		ODP_ASSERT(status & RxRES);

		/* FIXME: don't include FCS */
		/* FIXME: use proper macro to mask packet length from status */
		pkt_len = (status & 0x00003fff) - 4;

		pkt = odp_packet_alloc(NULL /* pool */ , R8169_RX_BUF_SIZE);
		ODP_ASSERT(pkt != ODP_PACKET_INVALID); /* TODO */
		pkt_hdr = odp_packet_hdr(pkt);

		pull_tail(pkt_hdr, R8169_RX_BUF_SIZE - pkt_len);

		/* FIXME: check return value  */
		odp_packet_copy_from_mem(pkt, 0, pkt_len,
					 pkt_r8169->rx_data.vaddr +
					 pkt_r8169->rx_next *
					 R8169_RX_BUF_SIZE);

		pkt_hdr->input = pktio_entry->s.handle;

		pkt_r8169->rx_next++;
		if (pkt_r8169->rx_next >= NUM_RX_DESC)
			pkt_r8169->rx_next = 0;

		pkt_table[rx_pkts] = pkt;
		rx_pkts++;
	}

	r8169_rx_refill(pktio_entry, refill_from, rx_pkts);

	return rx_pkts;
}


static pktio_ops_module_t r8169_pktio_ops = {
	.base = {
		 .name = "r8169",
		 },

	.open = r8169_open,
	.close = r8169_close,

	.recv = r8169_recv,
};

/** r8169 module entry point */
static void ODPDRV_CONSTRUCTOR r8169_module_init(void)
{
	odp_module_constructor(&r8169_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &r8169_pktio_ops);
}
