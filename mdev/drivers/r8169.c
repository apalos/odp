#include <odp_posix_extensions.h>

#include <stdio.h>
#include <endian.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/types.h>

#include <odp/api/hints.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/packet.h>

#include <odp/drv/hints.h>

#include <odp_packet_io_internal.h>

#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>
#include <sysfs_parse.h>
#include <eth_stats.h>
#include <common.h>

#include <uapi/net_mdev.h>

#define MODULE_NAME "r8169"

#define R8169_RX_BUF_SIZE	2048U
#define R8169_TX_BUF_SIZE	2048U

#define R8169_TXPOLL	0x38
#define R8169_NPQ	0x40

typedef struct {
#define	RxRES		(1U << 21)
#define DescOwn		(1U << 31)	/* Descriptor is owned by NIC */
#define RingEnd		(1U << 30)	/* End of descriptor ring */
	odp_u32le_t opts1;
	odp_u32le_t opts2;
	odp_u64le_t addr;
} r8169_rx_desc_t;

typedef struct {
#define FirstFrag	(1U << 29)	/* First segment of a packet */
#define LastFrag	(1U << 28)	/* Final segment of a packet */
#define DescOwn		(1U << 31)	/* Descriptor is owned by NIC */
#define RingEnd		(1U << 30)	/* End of descriptor ring */
	odp_u32le_t opts1;
	odp_u32le_t opts2;
	odp_u64le_t addr;
} r8169_tx_desc_t;

/** Packet socket using mediated r8169 device */
typedef struct {
	/* RX queue hot data */
	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_ticketlock_t rx_lock;	/**< RX queue lock */
	r8169_rx_desc_t *rx_descs;	/**< RX queue mmap */
	struct iomem rx_data;		/**< RX packet payload mmap */
	uint16_t rx_next;		/**< next entry in RX queue to use */
	uint16_t rx_queue_len;		/**< Number of RX desc entries */

	/* TX queue hot data */
	odp_bool_t lockless_tx;		/**< no locking for TX */
	odp_ticketlock_t tx_lock;	/**< TX queue lock */
	r8169_tx_desc_t *tx_descs;	/**< TX queue mmap */
	struct iomem tx_data;		/**< TX packet payload mmap */
	uint16_t tx_next;		/**< next entry in TX queue to use */
	uint16_t tx_queue_len;		/**< Number of TX desc entries */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	odp_pool_t pool;		/**< pool to alloc packets from */

	void *mmio;			/**< MMIO mmap */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_r8169_data_t;

static void r8169_rx_refill(pktio_ops_r8169_data_t *pkt_r8169,
			    uint16_t from, uint16_t num);
static void r8169_wait_link_up(pktio_entry_t *pktio_entry);
static int r8169_close(pktio_entry_t *pktio_entry);

static int r8169_send(pktio_entry_t *pktio_entry, int txq_idx ODP_UNUSED,
		      const odp_packet_t pkt_table[] ODP_UNUSED, int num)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	int tx_pkts = 0;

	if (!pkt_r8169->lockless_tx)
		odp_ticketlock_lock(&pkt_r8169->tx_lock);

	while (tx_pkts < num) {
		volatile r8169_tx_desc_t *txd =
			&pkt_r8169->tx_descs[pkt_r8169->tx_next];
		uint32_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);
		uint32_t offset = pkt_r8169->tx_next * R8169_TX_BUF_SIZE;
		uint32_t opts[2];
		uint32_t status;

		status = odp_le_to_cpu_32(txd->opts1);
		if (status & DescOwn)
			break;

		/* Skip oversized packets silently */
		if (pkt_len > R8169_TX_BUF_SIZE) {
			tx_pkts++;
			continue;
		}

		odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
				       pkt_r8169->tx_data.vaddr + offset);

		txd->addr =
		    odp_cpu_to_le_64(pkt_r8169->tx_data.iova + offset);
		/* FIXME no fragmentation support */
		opts[0] = DescOwn;
		opts[0] |= FirstFrag | LastFrag;
		/* FIXME No vlan support */
		opts[1] = 0;

		pkt_r8169->tx_next++;
		if (odp_unlikely(pkt_r8169->tx_next >= pkt_r8169->tx_queue_len))
			pkt_r8169->tx_next = 0;

		status = opts[0] | pkt_len | (RingEnd * !(pkt_r8169->tx_next));

		txd->opts1 = odp_cpu_to_le_32(status);
		txd->opts2 = odp_cpu_to_le_32(opts[1]);

		tx_pkts++;
	}

	dma_wmb();

	io_write8(R8169_NPQ, (char *)pkt_r8169->mmio + R8169_TXPOLL);

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

static int r8169_mmio_register(pktio_ops_r8169_data_t *pkt_r8169,
			       uint64_t offset, uint64_t size)
{
	ODP_ASSERT(pkt_r8169->mmio == NULL);

	pkt_r8169->mmio = mdev_region_mmap(&pkt_r8169->mdev, offset, size);
	if (pkt_r8169->mmio == MAP_FAILED) {
		ODP_ERR("Cannot mmap MMIO\n");
		return -1;
	}

	ODP_DBG("Register MMIO region: 0x%llx@%016llx\n", size, offset);

	return 0;
}

static int r8169_rx_queue_register(pktio_ops_r8169_data_t *pkt_r8169,
				   uint64_t offset, uint64_t size)
{
	int ret;

	ODP_ASSERT(pkt_r8169->capa.max_input_queues == 0);

	pkt_r8169->rx_queue_len = 256; /* no ethtool support in r8169 */

	pkt_r8169->rx_descs = mdev_region_mmap(&pkt_r8169->mdev, offset, size);
	if (pkt_r8169->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
		return -1;
	}

	pkt_r8169->rx_data.size = pkt_r8169->rx_queue_len * R8169_RX_BUF_SIZE;
	ret = iomem_alloc_dma(&pkt_r8169->mdev, &pkt_r8169->rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}

	r8169_rx_refill(pkt_r8169, 0, pkt_r8169->rx_queue_len);

	pkt_r8169->capa.max_input_queues++;

	ODP_DBG("Register RX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX descriptors: %u\n", pkt_r8169->rx_queue_len);

	return 0;
}

static int r8169_tx_queue_register(pktio_ops_r8169_data_t *pkt_r8169,
				   uint64_t offset, uint64_t size)
{
	int ret;

	ODP_ASSERT(pkt_r8169->capa.max_output_queues == 0);

	pkt_r8169->tx_queue_len = 64; /* no ethtool support in r8169 */

	pkt_r8169->tx_descs = mdev_region_mmap(&pkt_r8169->mdev, offset, size);
	if (pkt_r8169->tx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap TX queue\n");
		return -1;
	}

	pkt_r8169->tx_data.size = pkt_r8169->tx_queue_len * R8169_TX_BUF_SIZE;
	ret = iomem_alloc_dma(&pkt_r8169->mdev, &pkt_r8169->tx_data);
	if (ret) {
		ODP_ERR("Cannot allocate TX queue DMA area\n");
		return -1;
	}

	pkt_r8169->capa.max_output_queues++;

	ODP_DBG("Register TX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    TX descriptors: %u\n", pkt_r8169->tx_queue_len);

	return 0;
}

static int r8169_region_info_cb(mdev_device_t *mdev,
				struct vfio_region_info *region_info)
{
	pktio_ops_r8169_data_t *pkt_r8169 =
	    odp_container_of(mdev, pktio_ops_r8169_data_t, mdev);
	int ret;
	mdev_region_class_t class_info;

	ret = vfio_get_region_cap_type(region_info, &class_info);
	if (ret < 0)
		return ret;

	switch (class_info.type) {
	case VFIO_NET_MMIO:
		ret =
		    r8169_mmio_register(pkt_r8169, region_info->offset,
					region_info->size);
		break;

	case VFIO_NET_DESCRIPTORS:
		if (class_info.subtype == VFIO_NET_MDEV_RX)
			ret =
			    r8169_rx_queue_register(pkt_r8169,
						    region_info->offset,
						    region_info->size);
		else if (class_info.subtype == VFIO_NET_MDEV_TX)
			ret =
			    r8169_tx_queue_register(pkt_r8169,
						    region_info->offset,
						    region_info->size);
		break;

	default:
		ODP_ERR("Unexpected region %u type: %d\n", region_info->index,
			class_info.type);
		ret = -1;
		break;
	}

	return ret;
}

static int r8169_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		      const char *resource, odp_pool_t pool)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	int ret;

	ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	memset(pkt_r8169, 0, sizeof(*pkt_r8169));

	ODP_DBG("%s: probing resource %s\n", MODULE_NAME, resource);

	ret =
	    mdev_device_create(&pkt_r8169->mdev, MODULE_NAME,
			       resource + strlen(NET_MDEV_PREFIX),
			       r8169_region_info_cb);
	if (ret)
		goto out;

	pkt_r8169->pool = pool;

	odp_ticketlock_init(&pkt_r8169->rx_lock);
	odp_ticketlock_init(&pkt_r8169->tx_lock);

	r8169_wait_link_up(pktio_entry);

	ODP_DBG("%s: open %s is successful\n", MODULE_NAME,
		pkt_r8169->mdev.if_name);

	return 0;

out:
	r8169_close(pktio_entry);
	return -1;
}

static int r8169_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);

	ODP_DBG("%s: close %s\n", MODULE_NAME, pkt_r8169->mdev.if_name);

	mdev_device_destroy(&pkt_r8169->mdev);

	if (pkt_r8169->tx_data.vaddr)
		iomem_free_dma(&pkt_r8169->mdev, &pkt_r8169->tx_data);
	if (pkt_r8169->rx_data.vaddr)
		iomem_free_dma(&pkt_r8169->mdev, &pkt_r8169->rx_data);

	return 0;
}

static void r8169_rx_refill(pktio_ops_r8169_data_t *pkt_r8169,
			    uint16_t from, uint16_t num)
{
	uint16_t i = from;

	ODP_ASSERT(num <= pkt_r8169->rx_queue_len);

	while (num) {
		r8169_rx_desc_t *rxd = &pkt_r8169->rx_descs[i];
		uint32_t offset = i * R8169_RX_BUF_SIZE;
		uint32_t opts1;

		rxd->addr =
		    odp_cpu_to_le_64(pkt_r8169->rx_data.iova + offset);
		rxd->opts2 = odp_cpu_to_le_32(0);

		if (odp_likely(i < pkt_r8169->rx_queue_len - 1)) {
			opts1 = DescOwn | R8169_RX_BUF_SIZE;
			i++;
		} else {
			opts1 = DescOwn | R8169_RX_BUF_SIZE | RingEnd;
			i = 0;
		}
		num--;

		dma_wmb();
		rxd->opts1 = odp_cpu_to_le_32(opts1);
	}
}

static int r8169_recv(pktio_entry_t *pktio_entry, int rxq_idx ODP_UNUSED,
		      odp_packet_t pkt_table[], int num)
{
	pktio_ops_r8169_data_t *pkt_r8169 = odp_ops_data(pktio_entry, r8169);
	uint16_t refill_from;
	int rx_pkts = 0;
	int ret;

	/* Keep track of the start point to refill RX queue */
	refill_from = pkt_r8169->rx_next;

	while (rx_pkts < num) {
		volatile r8169_rx_desc_t *rxd =
		    &pkt_r8169->rx_descs[pkt_r8169->rx_next];
		odp_packet_hdr_t *pkt_hdr;
		odp_packet_t pkt;
		uint16_t pkt_len;
		uint32_t status;

		status = odp_le_to_cpu_32(rxd->opts1);
		if (status & DescOwn)
			break;

		dma_rmb();

		/* FIXME: let the HW drop all erroneous packets */
		ODP_ASSERT(status & RxRES);

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
		if (odp_unlikely(pkt_r8169->rx_next >= pkt_r8169->rx_queue_len))
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

	return mdev_get_iff_link(pkt_r8169->mdev.if_name);
}

/* TODO: move to common code */
static void r8169_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!r8169_link_status(pktio_entry))
		sleep(1);
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
