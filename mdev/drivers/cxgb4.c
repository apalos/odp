#include "config.h"

#include <odp_posix_extensions.h>

#include <stdio.h>
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

#include <protocols/eth.h>

#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>
#include <ethtool_api.h>
#include <sysfs_parse.h>
#include <eth_stats.h>
#include <common.h>

#include <uapi/net_mdev.h>

#define MODULE_NAME "cxgb4"

#define CXGB4_TX_BUF_SIZE 2048U

#define CXGB4_TX_INLINE_MAX (256 - sizeof(cxgb4_fw_eth_tx_pkt_wr_t) \
				 - sizeof(cxgb4_cpl_tx_pkt_core_t))

/* RX queue definitions */
#define CXGB4_RX_QUEUE_NUM_MAX 32

/** RX descriptor */
typedef struct {
	uint32_t padding[12];

	odp_u32be_t hdrbuflen_pidx;
#define RX_DESC_NEW_BUF_FLAG	(1U << 31)
	odp_u32be_t pldbuflen_qid;
	union {
#define RX_DESC_GEN_SHIFT	7
#define RX_DESC_GEN_MASK	0x1
#define RX_DESC_TYPE_SHIFT	4
#define RX_DESC_TYPE_MASK	0x3
#define RX_DESC_TYPE_FLBUF_X	0
#define RX_DESC_TYPE_CPL_X	1
#define RX_DESC_TYPE_INTR_X	2
		uint8_t type_gen;
#define RX_DESC_TIMESTAMP_MASK	0xfffffffffffffffULL
		odp_u64be_t last_flit;
	};
} cxgb4_rx_desc_t;

#define RX_DESC_TO_GEN(rxd) \
	(((rxd)->type_gen >> RX_DESC_GEN_SHIFT) & RX_DESC_GEN_MASK)
#define RX_DESC_TO_TYPE(rxd) \
	(((rxd)->type_gen >> RX_DESC_TYPE_SHIFT) & RX_DESC_TYPE_MASK)

/** RX queue data */
typedef struct {
	cxgb4_rx_desc_t *rx_descs;	/**< RX queue base */

	odp_u32le_t *doorbell_fl;	/**< Free list refill doorbell */
	odp_u32le_t *doorbell_desc;	/**< Rx descriptor free doorbell */
	uint32_t doorbell_fl_key;	/**< 'Key' to the doorbell */
	uint32_t doorbell_desc_key;	/**< 'Key' to the doorbell */

	uint16_t rx_queue_len;		/**< Number of RX desc entries */
	uint16_t rx_next;		/**< Next RX desc to handle */

	uint8_t *rx_data_base;		/**< RX packet payload area VA */
	uint64_t rx_data_iova;		/**< RX packet payload area IOVA */
	uint32_t rx_data_size;		/**< RX packet payload area size */

	uint32_t gen:1;			/**< RX queue generation */
	uint32_t padding:31;

	odp_u64be_t *free_list;	/**< Free list base */

	uint8_t free_list_len;		/**< Number of free list entries */
	uint8_t commit_pending;		/**< Free list entries pending commit */

	uint8_t cidx;			/**< Free list consumer index */
	uint8_t pidx;			/**< Free list producer index */

	uint32_t offset;		/**< Offset into last free fragment */
} cxgb4_rx_queue_t ODP_ALIGNED_CACHE;

/* TX queue definitions */
#define CXGB4_TX_QUEUE_NUM_MAX 32

typedef struct {
	odp_u64be_t data[8];
} cxgb4_tx_desc_t;

typedef struct {
#define CXGB4_FW_ETH_TX_PKT_WR 0x08000000UL
	odp_u32be_t op_immdlen;
	odp_u32be_t equiq_to_len16;
	odp_u64be_t r3;
} cxgb4_fw_eth_tx_pkt_wr_t;

typedef struct {
#define CPL_TX_PKT_XT	0xEE000000UL
#define TXPKT_PF_S	8
#define TXPKT_PF_V(x)	((x) << TXPKT_PF_S)
#define TXPKT_INTF_S	16
#define TXPKT_INTF_V(x)	((x) << TXPKT_INTF_S)
	odp_u32be_t ctrl0;
	odp_u16be_t pack;
	odp_u16be_t len;
#define TXPKT_IPCSUM_DIS_F (1UL << 62)
#define TXPKT_L4CSUM_DIS_F (1UL << 63)
	odp_u64be_t ctrl1;
} cxgb4_cpl_tx_pkt_core_t;

typedef struct {
	odp_u32be_t len[2];
	odp_u64be_t addr[2];
} cxgb4_sg_pair_t;

typedef struct {
#define CXGB4_ULP_TX_SC_DSGL (0x82UL << 24)
	odp_u32be_t sg_pairs_num;
	odp_u32be_t len0;
	odp_u64be_t addr0;
	cxgb4_sg_pair_t sg_pairs[0];
} cxgb4_sg_list_t;

typedef struct {
	odp_u32be_t qid;
	odp_u16be_t cidx;
	odp_u16be_t pidx;
} cxgb4_tx_queue_stats;

/** TX queue data */
typedef struct {
	cxgb4_tx_desc_t *tx_descs;	/**< TX queue base */
	cxgb4_tx_queue_stats *stats;	/**< TX queue stats */

	odp_u32le_t *doorbell_desc;	/**< TX queue doorbell */
	uint32_t doorbell_desc_key;	/**< 'Key' to the doorbell */

	uint16_t tx_queue_len;		/**< Number of TX desc entries */
	uint16_t tx_next;		/**< Next TX desc to insert */

	uint8_t *tx_data_base;		/**< TX packet payload area VA */
	uint64_t tx_data_iova;		/**< TX packet payload area IOVA */
	uint32_t tx_data_size;		/**< TX packet payload area size */

	uint32_t padding[3];
} cxgb4_tx_queue_t ODP_ALIGNED_CACHE;

/** Packet socket using mediated cxgb4 device */
typedef struct {
	/** RX queue hot data */
	cxgb4_rx_queue_t rx_queues[CXGB4_RX_QUEUE_NUM_MAX];

	/** TX queue hot data */
	cxgb4_tx_queue_t tx_queues[CXGB4_TX_QUEUE_NUM_MAX];

	/** RX queue locks */
	odp_ticketlock_t rx_locks[CXGB4_RX_QUEUE_NUM_MAX];
	odp_ticketlock_t tx_locks[CXGB4_TX_QUEUE_NUM_MAX];

	odp_pool_t pool;		/**< pool to alloc packets from */

	odp_bool_t lockless_rx;		/**< no locking for RX */
	uint16_t free_list_align;	/**< Alignment required for RX chunks */

	odp_bool_t lockless_tx;		/**< no locking for TX */
	uint8_t tx_channel;		/**< TX channel of the interface */
	uint8_t phys_function;		/**< Physical function of the interface */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	uint8_t *mmio;			/**< MMIO region */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_cxgb4_data_t;

static void cxgb4_rx_refill(cxgb4_rx_queue_t *rxq, uint8_t num);
static void cxgb4_wait_link_up(pktio_entry_t *pktio_entry);
static int cxgb4_close(pktio_entry_t *pktio_entry);

static int cxgb4_mmio_register(pktio_ops_cxgb4_data_t *pkt_cxgb4,
			       uint64_t offset, uint64_t size)
{
	ODP_ASSERT(pkt_cxgb4->mmio == NULL);

	pkt_cxgb4->mmio = mdev_region_mmap(&pkt_cxgb4->mdev, offset, size);
	if (pkt_cxgb4->mmio == MAP_FAILED) {
		ODP_ERR("Cannot mmap MMIO\n");
		return -1;
	}

	ODP_DBG("Register MMIO region: 0x%llx@%016llx\n", size, offset);

	return 0;
}

static int cxgb4_rx_queue_register(pktio_ops_cxgb4_data_t *pkt_cxgb4,
				   uint64_t offset, uint64_t size,
				   uint64_t free_list_offset)
{
	uint16_t rxq_idx = pkt_cxgb4->capa.max_input_queues++;
	cxgb4_rx_queue_t *rxq = &pkt_cxgb4->rx_queues[rxq_idx];
	uint32_t doorbell_fl_offset, doorbell_desc_offset;
	struct iomem rx_data;
	struct ethtool_ringparam ering;
	char path[2048];
	int ret;

	ODP_ASSERT(rxq_idx < ARRAY_SIZE(pkt_cxgb4->rx_queues));

	memset(path, 0, sizeof(path));

	ret = mdev_ringparam_get(&pkt_cxgb4->mdev, &ering);
	if (ret) {
		ODP_ERR("Cannot get ethtool parameters\n");
		return -1;
	}
	rxq->rx_queue_len = ering.rx_mini_pending;
	rxq->free_list_len = ering.rx_pending + 8;

	snprintf(path, sizeof(path) - 1, "queues/rx-%u/cxgb4/doorbell_fl_offset",
		 rxq_idx);
	if (mdev_attr_u32_get(&pkt_cxgb4->mdev, path, &doorbell_fl_offset) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}
	rxq->doorbell_fl = (odp_u32le_t *)(pkt_cxgb4->mmio + doorbell_fl_offset);

	snprintf(path, sizeof(path) - 1, "queues/rx-%u/cxgb4/doorbell_fl_key",
		 rxq_idx);
	if (mdev_attr_u32_get(&pkt_cxgb4->mdev, path, &rxq->doorbell_fl_key) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}

	snprintf(path, sizeof(path) - 1, "queues/rx-%u/cxgb4/doorbell_desc_offset",
		 rxq_idx);
	if (mdev_attr_u32_get(&pkt_cxgb4->mdev, path, &doorbell_desc_offset) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}
	rxq->doorbell_desc = (odp_u32le_t *)(pkt_cxgb4->mmio +
			doorbell_desc_offset);

	snprintf(path, sizeof(path) - 1, "queues/rx-%u/cxgb4/doorbell_desc_key",
		 rxq_idx);
	if (mdev_attr_u32_get(&pkt_cxgb4->mdev, path, &rxq->doorbell_desc_key) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}

	ODP_ASSERT(rxq->rx_queue_len * sizeof(*rxq->rx_descs) <= size);

	rxq->rx_descs = mdev_region_mmap(&pkt_cxgb4->mdev, offset, size);
	if (rxq->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
		return -1;
	}

	ODP_ASSERT(rxq->free_list_len * sizeof(*rxq->free_list) <=
		   ODP_PAGE_SIZE);

	rxq->free_list =
	    mdev_region_mmap(&pkt_cxgb4->mdev, free_list_offset, ODP_PAGE_SIZE);
	if (rxq->free_list == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue free list\n");
		return -1;
	}

	rx_data.size = rxq->free_list_len * ODP_PAGE_SIZE;
	ret = iomem_alloc_dma(&pkt_cxgb4->mdev, &rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}
	rxq->rx_data_base = rx_data.vaddr;
	rxq->rx_data_iova = rx_data.iova;
	rxq->rx_data_size = rx_data.size;
	rxq->gen = 1;

	/*
	 * Leave 1 HW block (8 entries) unpopulated,
	 * otherwise HW will think the free list is empty.
	 */
	cxgb4_rx_refill(rxq, rxq->free_list_len - 8);
	rxq->cidx = rxq->free_list_len - 1;

	ODP_DBG("Register RX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX descriptors: %u\n", rxq->rx_queue_len);
	ODP_DBG("    RX free list entries: %u\n", rxq->free_list_len);

	return 0;
}

static int cxgb4_tx_queue_register(pktio_ops_cxgb4_data_t *pkt_cxgb4,
				   uint64_t offset, uint64_t size)
{
	uint16_t txq_idx = pkt_cxgb4->capa.max_output_queues++;
	cxgb4_tx_queue_t *txq = &pkt_cxgb4->tx_queues[txq_idx];
	uint32_t doorbell_desc_offset;
	struct iomem tx_data;
	struct ethtool_ringparam ering;
	char path[2048];
	int ret;

	ODP_ASSERT(txq_idx < ARRAY_SIZE(pkt_cxgb4->tx_queues));

	memset(path, 0, sizeof(path));

	ret = mdev_ringparam_get(&pkt_cxgb4->mdev, &ering);
	if (ret) {
		ODP_ERR("Cannot get ethtool parameters\n");
		return -1;
	}
	txq->tx_queue_len = ering.tx_pending;

	snprintf(path, sizeof(path) - 1, "queues/tx-%u/cxgb4/doorbell_desc_offset",
		 txq_idx);
	if (mdev_attr_u32_get(&pkt_cxgb4->mdev, path, &doorbell_desc_offset) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}
	txq->doorbell_desc = (odp_u32le_t *)(pkt_cxgb4->mmio +
			doorbell_desc_offset);

	snprintf(path, sizeof(path) - 1, "queues/tx-%u/cxgb4/doorbell_desc_key",
		 txq_idx);
	if (mdev_attr_u32_get(&pkt_cxgb4->mdev, path, &txq->doorbell_desc_key) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}

	ODP_ASSERT(txq->tx_queue_len * sizeof(*txq->tx_descs) +
		   sizeof(*txq->stats) <= size);

	txq->tx_descs = mdev_region_mmap(&pkt_cxgb4->mdev, offset, size);
	if (txq->tx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap TX queue\n");
		return -1;
	}

	txq->stats =
	    (cxgb4_tx_queue_stats *)(txq->tx_descs + txq->tx_queue_len);

	tx_data.size = txq->tx_queue_len * CXGB4_TX_BUF_SIZE;
	ret = iomem_alloc_dma(&pkt_cxgb4->mdev, &tx_data);
	if (ret) {
		ODP_ERR("Cannot allocate TX queue DMA area\n");
		return -1;
	}
	txq->tx_data_base = tx_data.vaddr;
	txq->tx_data_iova = tx_data.iova;
	txq->tx_data_size = tx_data.size;

	ODP_DBG("Register TX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    TX descriptors: %u\n", txq->tx_queue_len);

	return 0;
}

static int cxgb4_region_info_cb(mdev_device_t *mdev,
				struct vfio_region_info *region_info)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 =
	    odp_container_of(mdev, pktio_ops_cxgb4_data_t, mdev);
	mdev_region_class_t class_info;

	if (vfio_get_region_cap_type(region_info, &class_info) < 0) {
		ODP_ERR("Cannot find class_info in region %u\n",
			region_info->index);
		return -1;
	}

	switch (class_info.type) {
	case VFIO_NET_MMIO:
		return cxgb4_mmio_register(pkt_cxgb4,
					   region_info->offset,
					   region_info->size);

	case VFIO_NET_DESCRIPTORS:
		if (class_info.subtype == VFIO_NET_MDEV_RX) {
			struct vfio_region_info_cap_sparse_mmap *sparse;

			if (vfio_get_region_sparse_mmaps(region_info,
							 &sparse) < 0) {
				ODP_ERR("RX queue in region %u: %s\n",
					region_info->index,
					"no areas found");
				return -1;
			}

			if (sparse->nr_areas != 2) {
				ODP_ERR("RX queue in region %u: %s\n",
					region_info->index,
					"wrong number of areas");
				return -1;
			}

			ODP_ASSERT(sparse->areas[1].size == ODP_PAGE_SIZE);

			return cxgb4_rx_queue_register(pkt_cxgb4,
						       sparse->areas[0].offset,
						       sparse->areas[0].size,
						       sparse->areas[1].offset);
		}
		if (class_info.subtype == VFIO_NET_MDEV_TX)
			return cxgb4_tx_queue_register(pkt_cxgb4,
						       region_info->offset,
						       region_info->size);
		/* fallthrough */

	default:
		ODP_ERR("Unexpected region %u (class %u:%u)\n",
			region_info->index, class_info.type,
			class_info.subtype);
		return -1;
	}
}

static int cxgb4_open(odp_pktio_t id ODP_UNUSED,
		      pktio_entry_t *pktio_entry,
		      const char *resource, odp_pool_t pool)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);
	int ret;

	ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	memset(pkt_cxgb4, 0, sizeof(*pkt_cxgb4));

	ODP_DBG("%s: probing resource %s\n", MODULE_NAME, resource);

	ret =
	    mdev_device_create(&pkt_cxgb4->mdev, MODULE_NAME,
			       resource + strlen(NET_MDEV_PREFIX),
			       cxgb4_region_info_cb);
	if (ret)
		goto out;

	pkt_cxgb4->pool = pool;

	for (uint32_t i = 0; i < ARRAY_SIZE(pkt_cxgb4->rx_locks); i++)
		odp_ticketlock_init(&pkt_cxgb4->rx_locks[i]);
	for (uint32_t i = 0; i < ARRAY_SIZE(pkt_cxgb4->tx_locks); i++)
		odp_ticketlock_init(&pkt_cxgb4->tx_locks[i]);

	if (mdev_attr_u8_get(&pkt_cxgb4->mdev, "tx_channel",
			     &pkt_cxgb4->tx_channel) < 0) {
		ODP_ERR("Cannot get %s\n", "tx_channel");
		goto out;
	}

	if (mdev_attr_u8_get(&pkt_cxgb4->mdev, "phys_function",
			     &pkt_cxgb4->phys_function) < 0) {
		ODP_ERR("Cannot get %s\n", "phys_function");
		goto out;
	}

	if (mdev_attr_u16_get(&pkt_cxgb4->mdev, "free_list_align",
			      &pkt_cxgb4->free_list_align) < 0) {
		ODP_ERR("Cannot get %s\n", "free_list_align");
		goto out;
	}

	cxgb4_wait_link_up(pktio_entry);

	ODP_DBG("%s: open %s is successful\n", MODULE_NAME,
		pkt_cxgb4->mdev.if_name);

	return 0;

out:
	cxgb4_close(pktio_entry);
	return -1;
}

static int cxgb4_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);

	ODP_DBG("%s: close %s\n", MODULE_NAME, pkt_cxgb4->mdev.if_name);

	mdev_device_destroy(&pkt_cxgb4->mdev);

	for (uint16_t i = 0; i < pkt_cxgb4->capa.max_input_queues; i++) {
		cxgb4_rx_queue_t *rxq = &pkt_cxgb4->rx_queues[i];

		if (rxq->rx_data_size) {
			struct iomem rx_data;

			rx_data.vaddr = rxq->rx_data_base;
			rx_data.iova = rxq->rx_data_iova;
			rx_data.size = rxq->rx_data_size;

			iomem_free_dma(&pkt_cxgb4->mdev, &rx_data);
		}
	}

	for (uint16_t i = 0; i < pkt_cxgb4->capa.max_output_queues; i++) {
		cxgb4_tx_queue_t *txq = &pkt_cxgb4->tx_queues[i];

		if (txq->tx_data_size) {
			struct iomem tx_data;

			tx_data.vaddr = txq->tx_data_base;
			tx_data.iova = txq->tx_data_iova;
			tx_data.size = txq->tx_data_size;

			iomem_free_dma(&pkt_cxgb4->mdev, &tx_data);
		}
	}

	return 0;
}

static void cxgb4_rx_refill(cxgb4_rx_queue_t *rxq, uint8_t num)
{
	rxq->commit_pending += num;

	while (num) {
		uint64_t iova = rxq->rx_data_iova + rxq->pidx * ODP_PAGE_SIZE;

		rxq->free_list[rxq->pidx] = odp_cpu_to_be_64(iova);

		rxq->pidx++;
		if (odp_unlikely(rxq->pidx >= rxq->free_list_len))
			rxq->pidx = 0;

		num--;
	}

	/* We commit free list entries to HW in packs of 8 */
	if (rxq->commit_pending >= 8) {
		uint32_t val = rxq->doorbell_fl_key | (rxq->commit_pending / 8);

		/* Ring the doorbell */
		dma_wmb();
		io_write32(odp_cpu_to_le_32(val), rxq->doorbell_fl);

		rxq->commit_pending &= 7;
	}
}

static int cxgb4_recv(pktio_entry_t *pktio_entry,
		      int rxq_idx, odp_packet_t pkt_table[], int num)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);
	cxgb4_rx_queue_t *rxq = &pkt_cxgb4->rx_queues[rxq_idx];
	uint16_t refill_count = 0;
	int rx_pkts = 0;

	if (!pkt_cxgb4->lockless_rx)
		odp_ticketlock_lock(&pkt_cxgb4->rx_locks[rxq_idx]);

	while (rx_pkts < num) {
		volatile cxgb4_rx_desc_t *rxd = &rxq->rx_descs[rxq->rx_next];
		odp_packet_t pkt;
		uint32_t pkt_len;
		uint8_t type;

		dma_rmb();
		if (RX_DESC_TO_GEN(rxd) != rxq->gen)
			break;

		type = RX_DESC_TO_TYPE(rxd);

		if (odp_unlikely(type != RX_DESC_TYPE_FLBUF_X)) {
			ODP_ERR("Invalid rxd type %u\n", type);

			rxq->rx_next++;
			if (odp_unlikely(rxq->rx_next >= rxq->rx_queue_len)) {
				rxq->rx_next = 0;
				rxq->gen ^= 1;
			}

			continue;
		}

		pkt_len = odp_be_to_cpu_32(rxd->pldbuflen_qid);

		/*
		 * HW skips trailing area in current RX buffer and starts in the
		 * next one from the beginning.
		 */
		if (pkt_len & RX_DESC_NEW_BUF_FLAG) {
			rxq->cidx++;
			if (odp_unlikely(rxq->cidx >= rxq->free_list_len))
				rxq->cidx = 0;

			rxq->offset = 0;
			refill_count++;

			pkt_len ^= RX_DESC_NEW_BUF_FLAG;
		}

		if (odp_unlikely(rxq->offset + pkt_len > ODP_PAGE_SIZE)) {
			/* TODO: reset the HW and reinit ? */
			ODP_ABORT("Packet write beyond buffer boundary\n");
		}

		pkt = odp_packet_alloc(pkt_cxgb4->pool, pkt_len);
		if (odp_likely(pkt != ODP_PACKET_INVALID)) {
			odp_packet_hdr_t *pkt_hdr;

			/*
			 * NIC is aligning L2 header on 4-byte boundary, hence
			 * we need to strip 2 leading bytes.
			 */
			odp_packet_copy_from_mem(pkt, 0, pkt_len - 2,
						 rxq->rx_data_base +
						 rxq->cidx * ODP_PAGE_SIZE +
						 rxq->offset + 2);

			pkt_hdr = odp_packet_hdr(pkt);
			pkt_hdr->input = pktio_entry->s.handle;

			pkt_table[rx_pkts] = pkt;
			rx_pkts++;
		}

		rxq->offset +=
		    ROUNDUP_ALIGN(pkt_len, pkt_cxgb4->free_list_align);

		rxq->rx_next++;
		if (odp_unlikely(rxq->rx_next >= rxq->rx_queue_len)) {
			rxq->rx_next = 0;
			rxq->gen ^= 1;
		}
	}

	if (rx_pkts)
		io_write32(odp_cpu_to_le_32(rx_pkts | rxq->doorbell_desc_key),
			   rxq->doorbell_desc);

	if (refill_count)
		cxgb4_rx_refill(rxq, refill_count);

	if (!pkt_cxgb4->lockless_rx)
		odp_ticketlock_unlock(&pkt_cxgb4->rx_locks[rxq_idx]);

	return rx_pkts;
}

static int cxgb4_send(pktio_entry_t *pktio_entry,
		      int txq_idx, const odp_packet_t pkt_table[], int num)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);
	cxgb4_tx_queue_t *txq = &pkt_cxgb4->tx_queues[txq_idx];
	uint16_t budget, tx_txds = 0;
	int tx_pkts = 0;

	if (!pkt_cxgb4->lockless_tx)
		odp_ticketlock_lock(&pkt_cxgb4->tx_locks[txq_idx]);

	/* Determine how many packets will fit in TX queue */
	budget = txq->tx_queue_len - 1;
	budget -= txq->tx_next;
	budget += odp_be_to_cpu_16(txq->stats->cidx);
	budget &= txq->tx_queue_len - 1;

	while (budget && tx_pkts < num) {
		uint16_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);

		cxgb4_tx_desc_t *txd = &txq->tx_descs[txq->tx_next];
		uint32_t txd_len;

		cxgb4_fw_eth_tx_pkt_wr_t *wr;
		cxgb4_cpl_tx_pkt_core_t *cpl;
		uint32_t op_immdlen;

		/* Skip oversized packets silently */
		if (odp_unlikely(pkt_len > CXGB4_TX_BUF_SIZE)) {
			tx_pkts++;
			continue;
		}

		dma_rmb();

		wr = (cxgb4_fw_eth_tx_pkt_wr_t *)txd;
		cpl = (cxgb4_cpl_tx_pkt_core_t *)(wr + 1);

		txd_len = sizeof(*wr) + sizeof(*cpl);
		op_immdlen = CXGB4_FW_ETH_TX_PKT_WR | sizeof(*cpl);

		if (pkt_len <= CXGB4_TX_INLINE_MAX) {
			uint8_t *pos;
			uint32_t left;

			txd_len += pkt_len;

			/* Try next time */
			if (DIV_ROUND_UP(txd_len, sizeof(*txd)) > budget)
				break;

			op_immdlen += pkt_len;

			/* Packet copying shall take care of wrapping */
			pos = (uint8_t *)(cpl + 1);
			left = (uint8_t *)(txq->tx_descs + txq->tx_queue_len) -
			    pos;

			if (odp_likely(left >= pkt_len)) {
				odp_packet_copy_to_mem(pkt_table[tx_pkts], 0,
						       pkt_len, pos);
			} else {
				odp_packet_copy_to_mem(pkt_table[tx_pkts], 0,
						       left, pos);
				odp_packet_copy_to_mem(pkt_table[tx_pkts], left,
						       pkt_len - left,
						       &txq->tx_descs[0]);
			}
		} else {
			uint32_t offset = txq->tx_next * CXGB4_TX_BUF_SIZE;
			cxgb4_sg_list_t *sgl;

			txd_len += sizeof(*sgl);

			odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
					       txq->tx_data_base + offset);

			sgl = (cxgb4_sg_list_t *)(cpl + 1);

			sgl->sg_pairs_num =
			    odp_cpu_to_be_32(CXGB4_ULP_TX_SC_DSGL | 1);
			sgl->addr0 =
			    odp_cpu_to_be_64(txq->tx_data_iova + offset);
			sgl->len0 = odp_cpu_to_be_32(pkt_len);
		}

		wr->op_immdlen = odp_cpu_to_be_32(op_immdlen);
		wr->equiq_to_len16 =
		    odp_cpu_to_be_32(DIV_ROUND_UP(txd_len, 16));
		wr->r3 = odp_cpu_to_be_64(0);

		cpl->ctrl0 =
		    odp_cpu_to_be_32(CPL_TX_PKT_XT |
				     TXPKT_INTF_V(pkt_cxgb4->tx_channel) |
				     TXPKT_PF_V(pkt_cxgb4->phys_function));
		cpl->pack = odp_cpu_to_be_16(0);
		cpl->len = odp_cpu_to_be_16(pkt_len);
		cpl->ctrl1 =
		    odp_cpu_to_be_64(TXPKT_L4CSUM_DIS_F | TXPKT_IPCSUM_DIS_F);

		txq->tx_next += DIV_ROUND_UP(txd_len, sizeof(*txd));
		if (odp_unlikely(txq->tx_next >= txq->tx_queue_len))
			txq->tx_next -= txq->tx_queue_len;

		tx_txds += DIV_ROUND_UP(txd_len, sizeof(*txd));
		budget -= DIV_ROUND_UP(txd_len, sizeof(*txd));

		tx_pkts++;
	}

	dma_wmb();

	/* Ring the doorbell */
	io_write32(odp_cpu_to_le_32(txq->doorbell_desc_key | tx_txds),
		   txq->doorbell_desc);

	if (!pkt_cxgb4->lockless_tx)
		odp_ticketlock_unlock(&pkt_cxgb4->tx_locks[txq_idx]);

	odp_packet_free_multi(pkt_table, tx_pkts);

	return tx_pkts;
}

static int cxgb4_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);

	return mdev_get_iff_link(pkt_cxgb4->mdev.if_name);
}

/* TODO: move to common code */
static void cxgb4_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!cxgb4_link_status(pktio_entry))
		sleep(1);
}

static int cxgb4_capability(pktio_entry_t *pktio_entry,
			    odp_pktio_capability_t *capa)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);

	*capa = pkt_cxgb4->capa;
	return 0;
}

static pktio_ops_module_t cxgb4_pktio_ops = {
	.base = {
		 .name = MODULE_NAME,
	},

	.open = cxgb4_open,
	.close = cxgb4_close,

	.recv = cxgb4_recv,
	.send = cxgb4_send,

	.link_status = cxgb4_link_status,

	.capability = cxgb4_capability,
};

/** cxgb4 module entry point */
static void ODPDRV_CONSTRUCTOR cxgb4_module_init(void)
{
	odp_module_constructor(&cxgb4_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &cxgb4_pktio_ops);
}
