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

#define MODULE_NAME "i40e"

#define I40E_TX_BUF_SIZE 2048U
#define I40E_RX_BUF_SIZE 2048U

#define I40E_TX_PACKET_LEN_MIN 17

/* RX queue definitions */
#define I40E_RX_QUEUE_NUM_MAX 32

/** RX descriptor */
typedef struct {
	uint64_t padding[4];
} i40e_rx_desc_t;

/** RX queue data */
typedef struct {
	i40e_rx_desc_t *rx_descs;	/**< RX queue base */
	odp_u32le_t *doorbell;		/**< RX queue doorbell */

	uint16_t rx_queue_len;		/**< Number of RX desc entries */
	uint16_t rx_next;		/**< Next RX desc to handle */

	uint8_t *rx_data_base;		/**< RX packet payload area VA */
	uint64_t rx_data_iova;		/**< RX packet payload area IOVA */
	uint32_t rx_data_size;		/**< RX packet payload area size */
} i40e_rx_queue_t /* ODP_ALIGNED_CACHE */;

/* TX queue definitions */
#define I40E_TX_QUEUE_NUM_MAX 32

typedef struct {
	odp_u64le_t addr;

#define I40E_TXD_DTYPE_DATA	0UL

#define I40E_TXD_CMD_ICRC	0x0004UL
#define I40E_TXD_CMD_EOP	0x0001UL

#define I40E_TXD_QW1_CMD_S	4
#define I40E_TXD_QW1_L2TAG1_S	48
#define I40E_TXD_QW1_OFFSET_S	16
#define I40E_TXD_QW1_SIZE_S	34
	odp_u64le_t cmd_type_offset_size;
} i40e_tx_desc_t;

/** TX queue data */
typedef struct {
	i40e_tx_desc_t *tx_descs;	/**< TX queue base */
	odp_u32le_t *doorbell;		/**< TX queue doorbell */

	uint16_t tx_queue_len;		/**< Number of TX desc entries */
	uint16_t tx_next;		/**< Next TX desc to insert */

	odp_u32le_t *cidx;		/**< Last TX desc processed by HW */

	uint8_t *tx_data_base;		/**< TX packet payload area VA */
	uint64_t tx_data_iova;		/**< TX packet payload area IOVA */
	uint32_t tx_data_size;		/**< TX packet payload area size */
} i40e_tx_queue_t /* ODP_ALIGNED_CACHE */;

/** Packet socket using mediated i40e device */
typedef struct {
	/** RX queue hot data */
	i40e_rx_queue_t rx_queues[I40E_RX_QUEUE_NUM_MAX];

	/** TX queue hot data */
	i40e_tx_queue_t tx_queues[I40E_TX_QUEUE_NUM_MAX];

	/** RX queue locks */
	odp_ticketlock_t rx_locks[I40E_RX_QUEUE_NUM_MAX];
	odp_ticketlock_t tx_locks[I40E_TX_QUEUE_NUM_MAX];

	odp_pool_t pool;		/**< pool to alloc packets from */

	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_bool_t lockless_tx;		/**< no locking for TX */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	uint8_t *mmio;			/**< MMIO region */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_i40e_data_t;

static void i40e_rx_refill(i40e_rx_queue_t *rxq, uint8_t num);
static void i40e_wait_link_up(pktio_entry_t *pktio_entry);
static int i40e_close(pktio_entry_t *pktio_entry);

static int i40e_mmio_register(pktio_ops_i40e_data_t *pkt_i40e,
			      uint64_t offset, uint64_t size)
{
	ODP_ASSERT(pkt_i40e->mmio == NULL);

	pkt_i40e->mmio = mdev_region_mmap(&pkt_i40e->mdev, offset, size);
	if (pkt_i40e->mmio == MAP_FAILED) {
		ODP_ERR("Cannot mmap MMIO\n");
		return -1;
	}

	ODP_DBG("Register MMIO region: 0x%llx@%016llx\n", size, offset);

	return 0;
}

static int i40e_rx_queue_register(pktio_ops_i40e_data_t *pkt_i40e,
				  uint64_t offset, uint64_t size)
{
	uint16_t rxq_idx = pkt_i40e->capa.max_input_queues++;
	i40e_rx_queue_t *rxq = &pkt_i40e->rx_queues[rxq_idx];
	uint32_t doorbell_offset;
	struct iomem rx_data;
	struct ethtool_ringparam ering;
	char path[2048];
	int ret;

	ODP_ASSERT(rxq_idx < ARRAY_SIZE(pkt_i40e->rx_queues));

	ret = mdev_ringparam_get(&pkt_i40e->mdev, &ering);
	if (ret) {
		ODP_ERR("Cannot get ethtool parameters\n");
		return -1;
	}
	rxq->rx_queue_len = ering.rx_pending;

	snprintf(path, sizeof(path) - 1, "queues/rx-%u/i40e/doorbell_offset",
		 rxq_idx);
	if (mdev_attr_u32_get(&pkt_i40e->mdev, path, &doorbell_offset) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}
	rxq->doorbell = (odp_u32le_t *)(pkt_i40e->mmio + doorbell_offset);

	ODP_ASSERT(rxq->rx_queue_len * sizeof(*rxq->rx_descs) <= size);

	rxq->rx_descs = mdev_region_mmap(&pkt_i40e->mdev, offset, size);
	if (rxq->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
		return -1;
	}

	rx_data.size = rxq->rx_queue_len * I40E_RX_BUF_SIZE;
	ret = iomem_alloc_dma(&pkt_i40e->mdev, &rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}
	rxq->rx_data_base = rx_data.vaddr;
	rxq->rx_data_iova = rx_data.iova;
	rxq->rx_data_size = rx_data.size;

	i40e_rx_refill(rxq, rxq->rx_queue_len - 1);

	ODP_DBG("Register RX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX descriptors: %u\n", rxq->rx_queue_len);

	return 0;
}

static int i40e_tx_queue_register(pktio_ops_i40e_data_t *pkt_i40e,
				  uint64_t offset, uint64_t size)
{
	uint16_t txq_idx = pkt_i40e->capa.max_output_queues++;
	i40e_tx_queue_t *txq = &pkt_i40e->tx_queues[txq_idx];
	uint32_t doorbell_offset;
	struct iomem tx_data;
	struct ethtool_ringparam ering;
	char path[2048];
	int ret;

	ODP_ASSERT(txq_idx < ARRAY_SIZE(pkt_i40e->tx_queues));

	ret = mdev_ringparam_get(&pkt_i40e->mdev, &ering);
	if (ret) {
		ODP_ERR("Cannot get ethtool parameters\n");
		return -1;
	}
	txq->tx_queue_len = ering.tx_pending;

	snprintf(path, sizeof(path) - 1, "queues/tx-%u/i40e/doorbell_offset",
		 txq_idx);
	if (mdev_attr_u32_get(&pkt_i40e->mdev, path, &doorbell_offset) < 0) {
		ODP_ERR("Cannot get %s\n", path);
		return -1;
	}
	txq->doorbell = (odp_u32le_t *)(pkt_i40e->mmio + doorbell_offset);

	ODP_ASSERT(txq->tx_queue_len * sizeof(*txq->tx_descs) +
		   sizeof(*txq->cidx) <= size);

	txq->tx_descs = mdev_region_mmap(&pkt_i40e->mdev, offset, size);
	if (txq->tx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap TX queue\n");
		return -1;
	}

	txq->cidx = (odp_u32le_t *)(txq->tx_descs + txq->tx_queue_len);

	tx_data.size = txq->tx_queue_len * I40E_TX_BUF_SIZE;
	ret = iomem_alloc_dma(&pkt_i40e->mdev, &tx_data);
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

static int i40e_region_info_cb(mdev_device_t *mdev,
			       struct vfio_region_info *region_info)
{
	pktio_ops_i40e_data_t *pkt_i40e =
	    odp_container_of(mdev, pktio_ops_i40e_data_t, mdev);
	mdev_region_class_t class_info;

	if (vfio_get_region_cap_type(region_info, &class_info) < 0) {
		ODP_ERR("Cannot find class_info in region %u\n",
			region_info->index);
		return -1;
	}

	switch (class_info.type) {
	case VFIO_NET_MMIO:
		return i40e_mmio_register(pkt_i40e,
					   region_info->offset,
					   region_info->size);

	case VFIO_NET_DESCRIPTORS:
		if (class_info.subtype == VFIO_NET_MDEV_RX)
			return i40e_rx_queue_register(pkt_i40e,
						       region_info->offset,
						       region_info->size);
		if (class_info.subtype == VFIO_NET_MDEV_TX)
			return i40e_tx_queue_register(pkt_i40e,
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

static int i40e_open(odp_pktio_t id ODP_UNUSED,
		     pktio_entry_t *pktio_entry,
		     const char *resource, odp_pool_t pool)
{
	pktio_ops_i40e_data_t *pkt_i40e = odp_ops_data(pktio_entry, i40e);
	int ret;

	ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	memset(pkt_i40e, 0, sizeof(*pkt_i40e));

	ODP_DBG("%s: probing resource %s\n", MODULE_NAME, resource);

	ret =
	    mdev_device_create(&pkt_i40e->mdev, MODULE_NAME,
			       resource + strlen(NET_MDEV_PREFIX),
			       i40e_region_info_cb);
	if (ret)
		goto out;

	pkt_i40e->pool = pool;

	for (uint32_t i = 0; i < ARRAY_SIZE(pkt_i40e->rx_locks); i++)
		odp_ticketlock_init(&pkt_i40e->rx_locks[i]);
	for (uint32_t i = 0; i < ARRAY_SIZE(pkt_i40e->tx_locks); i++)
		odp_ticketlock_init(&pkt_i40e->tx_locks[i]);

	i40e_wait_link_up(pktio_entry);

	ODP_DBG("%s: open %s is successful\n", MODULE_NAME,
		pkt_i40e->mdev.if_name);

	return 0;

out:
	i40e_close(pktio_entry);
	return -1;
}

static int i40e_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_i40e_data_t *pkt_i40e = odp_ops_data(pktio_entry, i40e);

	ODP_DBG("%s: close %s\n", MODULE_NAME, pkt_i40e->mdev.if_name);

	mdev_device_destroy(&pkt_i40e->mdev);

	for (uint16_t i = 0; i < pkt_i40e->capa.max_input_queues; i++) {
		i40e_rx_queue_t *rxq = &pkt_i40e->rx_queues[i];

		if (rxq->rx_data_size) {
			struct iomem rx_data;

			rx_data.vaddr = rxq->rx_data_base;
			rx_data.iova = rxq->rx_data_iova;
			rx_data.size = rxq->rx_data_size;

			iomem_free_dma(&pkt_i40e->mdev, &rx_data);
		}
	}

	for (uint16_t i = 0; i < pkt_i40e->capa.max_output_queues; i++) {
		i40e_tx_queue_t *txq = &pkt_i40e->tx_queues[i];

		if (txq->tx_data_size) {
			struct iomem tx_data;

			tx_data.vaddr = txq->tx_data_base;
			tx_data.iova = txq->tx_data_iova;
			tx_data.size = txq->tx_data_size;

			iomem_free_dma(&pkt_i40e->mdev, &tx_data);
		}
	}

	return 0;
}

static void i40e_rx_refill(i40e_rx_queue_t *rxq ODP_UNUSED,
			   uint8_t num ODP_UNUSED)
{
}

static int i40e_recv(pktio_entry_t *pktio_entry, int rxq_idx,
		     odp_packet_t pkt_table[] ODP_UNUSED,
		     int num ODP_UNUSED)
{
	pktio_ops_i40e_data_t *pkt_i40e = odp_ops_data(pktio_entry, i40e);
	i40e_rx_queue_t *rxq ODP_UNUSED = &pkt_i40e->rx_queues[rxq_idx];
	int rx_pkts = 0;

	if (!pkt_i40e->lockless_rx)
		odp_ticketlock_lock(&pkt_i40e->rx_locks[rxq_idx]);

	if (!pkt_i40e->lockless_rx)
		odp_ticketlock_unlock(&pkt_i40e->rx_locks[rxq_idx]);

	return rx_pkts;
}

static uint64_t txd_ctos(uint32_t cmd, uint32_t tag, uint32_t offset,
			 uint32_t size)
{
	return I40E_TXD_DTYPE_DATA |
	    ((uint64_t)cmd << I40E_TXD_QW1_CMD_S) |
	    ((uint64_t)tag << I40E_TXD_QW1_L2TAG1_S) |
	    ((uint64_t)offset << I40E_TXD_QW1_OFFSET_S) |
	    ((uint64_t)size << I40E_TXD_QW1_SIZE_S);
}

static int i40e_send(pktio_entry_t *pktio_entry, int txq_idx,
		     const odp_packet_t pkt_table[], int num)
{
	pktio_ops_i40e_data_t *pkt_i40e = odp_ops_data(pktio_entry, i40e);
	i40e_tx_queue_t *txq = &pkt_i40e->tx_queues[txq_idx];
	uint16_t budget, tx_txds = 0;
	int tx_pkts = 0;

	if (!pkt_i40e->lockless_tx)
		odp_ticketlock_lock(&pkt_i40e->tx_locks[txq_idx]);

	/* Determine how many packets will fit in TX queue */
	budget = txq->tx_queue_len - 1;
	budget -= txq->tx_next;
	budget += odp_le_to_cpu_32(*txq->cidx);
	budget &= txq->tx_queue_len - 1;

	while (tx_txds < budget && tx_pkts < num) {
		uint16_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);
		uint32_t offset = txq->tx_next * I40E_TX_BUF_SIZE;

		i40e_tx_desc_t *txd = &txq->tx_descs[txq->tx_next];
		uint32_t txd_len = sizeof(*txd);

		uint32_t txd_cmd = I40E_TXD_CMD_ICRC | I40E_TXD_CMD_EOP;

		/* Skip undersized packets silently */
		if (odp_unlikely(pkt_len < I40E_TX_PACKET_LEN_MIN)) {
			tx_pkts++;
			continue;
		}

		/* Skip oversized packets silently */
		if (odp_unlikely(pkt_len > I40E_TX_BUF_SIZE)) {
			tx_pkts++;
			continue;
		}

		odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
				       txq->tx_data_base + offset);

		txd->addr = odp_cpu_to_le_64(txq->tx_data_iova + offset);
		txd->cmd_type_offset_size =
		    odp_cpu_to_le_64(txd_ctos(txd_cmd, 0, 0, pkt_len));

		txq->tx_next += DIV_ROUND_UP(txd_len, sizeof(*txd));
		if (odp_unlikely(txq->tx_next >= txq->tx_queue_len))
			txq->tx_next -= txq->tx_queue_len;

		tx_txds += DIV_ROUND_UP(txd_len, sizeof(*txd));

		tx_pkts++;
	}

	dma_wmb();

	/* Ring the doorbell */
	io_write32(odp_cpu_to_le_32(txq->tx_next), txq->doorbell);

	if (!pkt_i40e->lockless_tx)
		odp_ticketlock_unlock(&pkt_i40e->tx_locks[txq_idx]);

	odp_packet_free_multi(pkt_table, tx_pkts);

	return tx_pkts;
}

static int i40e_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_i40e_data_t *pkt_i40e = odp_ops_data(pktio_entry, i40e);

	return mdev_get_iff_link(pkt_i40e->mdev.if_name);
}

/* TODO: move to common code */
static void i40e_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!i40e_link_status(pktio_entry))
		sleep(1);
}

static pktio_ops_module_t i40e_pktio_ops = {
	.base = {
		 .name = MODULE_NAME,
	},

	.open = i40e_open,
	.close = i40e_close,

	.recv = i40e_recv,
	.send = i40e_send,

	.link_status = i40e_link_status,
};

/** i40e module entry point */
static void ODPDRV_CONSTRUCTOR i40e_module_init(void)
{
	odp_module_constructor(&i40e_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &i40e_pktio_ops);
}
