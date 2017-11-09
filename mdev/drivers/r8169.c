#include <odp_posix_extensions.h>

#include <stdio.h>
#include <endian.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/types.h>

#include <odp/drv/byteorder.h>
#include <odp/api/hints.h>
#include <odp/drv/hints.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/packet.h>

#include <odp_packet_io_internal.h>

#include <drivers/r8169.h>
#include <drivers/driver_ops.h>
#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>
#include <sysfs_parse.h>
#include <eth_stats.h>

#include <uapi/net_mdev.h>

#define MODULE_NAME "r8169"

/* Common code. TODO: relocate */
#if 1
typedef unsigned long dma_addr_t;
#endif

/** Packet socket using mediated r8169 device */
typedef struct {
	/* RX ring hot data */
	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_ticketlock_t rx_lock;	/**< RX ring lock */
	struct r8169_rxdesc *rx_ring;	/**< RX ring mmap */
	struct iomem rx_data;		/**< RX packet payload mmap */
	uint16_t rx_next;		/**< next entry in RX ring to use */

	/* TX ring hot data */
	odp_bool_t lockless_tx;		/**< no locking for TX */
	odp_ticketlock_t tx_lock;	/**< TX ring lock */
	struct r8169_txdesc *tx_ring;	/**< TX ring mmap */
	struct iomem tx_data;		/**< TX packet payload mmap */
	uint16_t tx_next;		/**< next entry in TX ring to use */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	odp_pool_t pool;		/**< pool to alloc packets from */

	void *mmio;			/**< MMIO mmap */
	size_t mmio_len;		/**< MMIO mmap'ed region length */

	size_t rx_ring_len;		/**< Rx ring mmap'ed region length */
	size_t tx_ring_len;		/**< Tx ring mmap'ed region length */

	mdev_device_t mdev;		/**< Common mdev data */

	char if_name[IF_NAMESIZE];	/** Interface name */
} pktio_ops_r8169_data_t;

static void r8169_rx_refill(pktio_ops_r8169_data_t *pkt_r8169,
			    uint16_t from, uint16_t num);
static void r8169_wait_link_up(pktio_entry_t *pktio_entry);
static int r8169_close(pktio_entry_t *pktio_entry);

static void r8169_flood(pktio_entry_t *pktio_entry)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	int tx_pkts;

	while (1) {
		tx_pkts = 0;
		while (tx_pkts < NUM_TX_DESC) {
			volatile struct r8169_txdesc *tx_desc =
				&pkt_r8169->tx_ring[pkt_r8169->tx_next];
			uint32_t pkt_len = 46;
			uint32_t offset = pkt_r8169->tx_next * R8169_TX_BUF_SIZE;
			uint32_t opts[2];
			uint32_t status;

			status = odpdrv_le_to_cpu_32(tx_desc->opts1);
			if (status & DescOwn)
				break;
			tx_desc->addr = odpdrv_cpu_to_le_64(pkt_r8169->tx_data.iova +
							    offset);
			/* FIXME no fragmentation support */
			opts[0] = DescOwn;
			opts[0] |= FirstFrag | LastFrag;
			/* FIXME No vlan support */
			opts[1] = 0;

			pkt_r8169->tx_next++;
			if (odp_unlikely(pkt_r8169->tx_next >= NUM_TX_DESC))
				pkt_r8169->tx_next = 0;

			status = opts[0] | pkt_len | (RingEnd * !(pkt_r8169->tx_next));

			tx_desc->opts1 = odpdrv_cpu_to_le_32(status);
			tx_desc->opts2 = odpdrv_cpu_to_le_32(opts[1]);

			tx_pkts++;
		}

		dma_wmb();
		io_write8(NPQ, (char *)pkt_r8169->mmio + TxPoll);
	}
}

static int r8169_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
		      const odp_packet_t pkt_table[] ODP_UNUSED, int num)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	int tx_pkts = 0;
	int flood = 0;

	if (!pkt_r8169->lockless_tx)
		odp_ticketlock_lock(&pkt_r8169->tx_lock);

	if (flood)
		r8169_flood(pktio_entry);

	while (tx_pkts < num) {
		volatile struct r8169_txdesc *tx_desc =
			&pkt_r8169->tx_ring[pkt_r8169->tx_next];
		uint32_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);
		uint32_t offset = pkt_r8169->tx_next * R8169_TX_BUF_SIZE;
		uint32_t opts[2];
		uint32_t status;

		status = odpdrv_le_to_cpu_32(tx_desc->opts1);
		if (status & DescOwn)
			break;
		/* Skip oversized packets silently */
		if (pkt_len > R8169_TX_BUF_SIZE) {
			tx_pkts++;
			continue;
		}

		odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
				       pkt_r8169->tx_data.vaddr + offset);

		tx_desc->addr = odpdrv_cpu_to_le_64(pkt_r8169->tx_data.iova + offset);
		/* FIXME no fragmentation support */
		opts[0] = DescOwn;
		opts[0] |= FirstFrag | LastFrag;
		/* FIXME No vlan support */
		opts[1] = 0;

		pkt_r8169->tx_next++;
		if (odp_unlikely(pkt_r8169->tx_next >= NUM_TX_DESC))
			pkt_r8169->tx_next = 0;

		status = opts[0] | pkt_len | (RingEnd * !(pkt_r8169->tx_next));

		tx_desc->opts1 = odpdrv_cpu_to_le_32(status);
		tx_desc->opts2 = odpdrv_cpu_to_le_32(opts[1]);

		tx_pkts++;
	}

	dma_wmb();

	io_write8(NPQ, (char *)pkt_r8169->mmio + TxPoll);

	if (!pkt_r8169->lockless_tx)
		odp_ticketlock_unlock(&pkt_r8169->tx_lock);

	if (odp_unlikely(tx_pkts == 0)) {
		if (odp_errno() != 0)
			return -1;
	} else {
		odp_packet_free_multi(pkt_table, tx_pkts);
	}

	return tx_pkts;
}

static int r8169_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		      const char *resource, odp_pool_t pool)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	int ret;

	// ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	/* Init pktio entry */
	memset(pkt_r8169, 0, sizeof(*pkt_r8169));
	strncpy(pkt_r8169->if_name, resource + strlen(NET_MDEV_PREFIX),
		sizeof(pkt_r8169->if_name) - 1);

	printf("%s: open %s\n", MODULE_NAME, pkt_r8169->if_name);

	ret = mdev_device_create(&pkt_r8169->mdev, MODULE_NAME, pkt_r8169->if_name);
	if (ret)
		goto out;

	pkt_r8169->pool = pool;

	pkt_r8169->capa.max_input_queues = 1;
	pkt_r8169->capa.max_output_queues = 1;

	odp_ticketlock_init(&pkt_r8169->rx_lock);
	odp_ticketlock_init(&pkt_r8169->tx_lock);

	pkt_r8169->mmio = vfio_mmap_region(&pkt_r8169->mdev, 2, &pkt_r8169->mmio_len);
	if (!pkt_r8169->mmio) {
		printf("Cannot map MMIO\n");
		goto out;
	}

	pkt_r8169->rx_ring = vfio_mmap_region(&pkt_r8169->mdev, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_RX_REGION_INDEX,
					      &pkt_r8169->rx_ring_len);
	if (!pkt_r8169->rx_ring) {
		printf("Cannot map RxRing\n");
		goto out;
	}
	pkt_r8169->tx_ring = vfio_mmap_region(&pkt_r8169->mdev, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_TX_REGION_INDEX,
					      &pkt_r8169->tx_ring_len);
	if (!pkt_r8169->tx_ring) {
		printf("Cannot map TxRing\n");
		goto out;
	}

	/* FIXME decide on allocated areas per hardware instead of getting 2MB
	 * per direction
	 */
	pkt_r8169->rx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(&pkt_r8169->mdev, &pkt_r8169->rx_data);
	if (ret)
		goto out;

	pkt_r8169->tx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(&pkt_r8169->mdev, &pkt_r8169->tx_data);
	if (ret)
		goto out;

	r8169_rx_refill(pkt_r8169, 0, NUM_RX_DESC);

	r8169_wait_link_up(pktio_entry);

	printf("%s: open %s is successful\n", MODULE_NAME, pkt_r8169->if_name);

	return 0;

out:
	r8169_close(pktio_entry);

	return -1;
}

static int r8169_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);

	printf("%s: close %s\n", MODULE_NAME, pkt_r8169->if_name);

	mdev_device_destroy(&pkt_r8169->mdev);

	if (pkt_r8169->tx_data.vaddr)
		iomem_free_dma(&pkt_r8169->mdev, &pkt_r8169->tx_data);
	if (pkt_r8169->rx_data.vaddr)
		iomem_free_dma(&pkt_r8169->mdev, &pkt_r8169->rx_data);
	if (pkt_r8169->tx_ring)
		munmap(pkt_r8169->tx_ring, pkt_r8169->tx_ring_len);
	if (pkt_r8169->rx_ring)
		munmap(pkt_r8169->rx_ring, pkt_r8169->rx_ring_len);
	if (pkt_r8169->mmio)
		munmap(pkt_r8169->mmio, pkt_r8169->mmio_len);

	return 0;
}

static void r8169_rx_refill(pktio_ops_r8169_data_t *pkt_r8169,
			    uint16_t from, uint16_t num)
{
	uint16_t i = from;

	// TODO: ODP_ASSERT(num <= NUM_RX_DESC);

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

static int r8169_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
		      odp_packet_t pkt_table[], int num)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	uint16_t refill_from;
	int rx_pkts = 0;
	int ret;

	/* Keep track of the start point to refill RX ring */
	refill_from = pkt_r8169->rx_next;

	while (rx_pkts < num) {
		volatile struct r8169_rxdesc *rx_desc =
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
		// TODO: ODP_ASSERT(status & RxRES);

		/* FIXME: don't include FCS */
		/* FIXME: use proper macro to mask packet length from status */
		pkt_len = (status & 0x00003fff) - 4;

		pkt = odp_packet_alloc(pkt_r8169->pool, R8169_RX_BUF_SIZE);
		if (odp_unlikely(pkt == ODP_PACKET_INVALID))
			break;

		pkt_hdr = odp_packet_hdr(pkt);

		pull_tail(pkt_hdr, R8169_RX_BUF_SIZE - pkt_len);

		ret = odp_packet_copy_from_mem(pkt, 0, pkt_len,
					       pkt_r8169->rx_data.vaddr +
					       pkt_r8169->rx_next *
					       R8169_RX_BUF_SIZE);
		if (odp_unlikely(ret != 0)) {
			odp_packet_free(pkt);
			break;
		}

		pkt_hdr->input = pktio_entry->s.handle;

		pkt_r8169->rx_next++;
		if (odp_unlikely(pkt_r8169->rx_next >= NUM_RX_DESC))
			pkt_r8169->rx_next = 0;

		pkt_table[rx_pkts] = pkt;
		rx_pkts++;
	}

	r8169_rx_refill(pkt_r8169, refill_from, rx_pkts);

	return rx_pkts;
}

static int r8169_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);

	return mdev_get_iff_link(pkt_r8169->if_name);
}

/* TODO: move to common code */
static void r8169_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!r8169_link_status(pktio_entry)) {
		sleep(1);
	}
}

static pktio_ops_module_t r8169_pktio_ops = {
	.base = {
		 .name = MODULE_NAME,
	},

	.open = r8169_open,
	.close = r8169_close,

	.recv = r8169_recv,
	.send = r8169_send,
	.link_status = r8169_link_status,
};

/** r8169 module entry point */
static void ODPDRV_CONSTRUCTOR r8169_module_init(void)
{
	odp_module_constructor(&r8169_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &r8169_pktio_ops);
}
