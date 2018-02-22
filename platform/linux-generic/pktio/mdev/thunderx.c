/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#if defined(_ODP_MDEV) && _ODP_MDEV == 1

#include <linux/types.h>
#include <protocols/eth.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <odp_packet_io_internal.h>
#include <odp_posix_extensions.h>

#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/drv/hints.h>
#include <odp/drv/mmio.h>

#include <pktio/common.h>
#include <pktio/ethtool.h>
#include <pktio/mdev.h>
#include <pktio/sysfs.h>
#include <pktio/uapi_net_mdev.h>

#define MODULE_NAME "thunder-nicvf"

/* RX queue definitions */
#define THUNDERX_RX_QUEUE_NUM_MAX	32
#define THUNDERX_RX_BUF_SIZE		2048UL

/** RX descriptor */
typedef struct {
} thunderx_rx_desc_t;

/** RX queue data */
typedef struct ODP_ALIGNED_CACHE {
	thunderx_rx_desc_t *rx_descs;	/**< RX queue base */
	odp_u32le_t *doorbell;		/**< RX queue doorbell */

	uint16_t rx_queue_len;		/**< Number of RX desc entries */

	mdev_dma_area_t rx_data;	/**< RX packet payload area */

	odp_ticketlock_t lock;		/**< RX queue lock */
} thunderx_rx_queue_t;

/* TX queue definitions */
#define THUNDERX_TX_QUEUE_NUM_MAX	8UL
#define THUNDERX_TX_BUF_SIZE		2048UL
#define THUNDERX_TX_PACKET_LEN_MIN	ETH_ALEN

#define THUNDERX_TXQ_HEAD_OFFSET(txq_idx) (0x010828UL + ((txq_idx) << 18))
#define THUNDERX_TXQ_DOOR_OFFSET(txq_idx) (0x010838UL + ((txq_idx) << 18))

/* Common TX descriptor field */
#define TXD_QW0_TYPE_V(type)		(((type) & UINT64_C(0xf)) << 60)

/* "Header" descriptor */
#define TXD_TYPE_HEADER			UINT64_C(0x1)
#define TXD_QW0_SUBDESC_COUNT_V(n)	(((n) & UINT64_C(0xff)) << 48)

/* "Gather" descriptor */
#define TXD_TYPE_GATHER			UINT64_C(0x4)
#define TXD_QW0_SIZE_V(size)		((size) & UINT64_C(0xffff))
#define TXD_QW1_ADDR_V(addr)		((addr) & UINT64_C(0x1ffffffffffff))

typedef struct {
	odp_u64le_t qw0;
	odp_u64le_t qw1;
} thunderx_tx_desc_t;

/** TX queue data */
typedef struct ODP_ALIGNED_CACHE {
	thunderx_tx_desc_t *tx_descs;	/**< TX queue base */
	odp_u64le_t *doorbell;		/**< TX queue doorbell */

	uint16_t tx_queue_len;		/**< Number of TX desc entries */
	uint16_t tx_txds_acc;		/**< TX descriptor accumulator */

	uint16_t pidx;			/**< Next TX desc to insert */
	odp_u64le_t *cidx;		/**< Last TX desc processed by HW */

	mdev_dma_area_t tx_data;	/**< TX packet payload area */

	odp_ticketlock_t lock;		/**< TX queue lock */
} thunderx_tx_queue_t;

/** Packet socket using mediated thunderx device */
typedef struct {
	/** RX queue hot data */
	thunderx_rx_queue_t rx_queues[THUNDERX_RX_QUEUE_NUM_MAX];

	/** TX queue hot data */
	thunderx_tx_queue_t tx_queues[THUNDERX_TX_QUEUE_NUM_MAX];

	odp_pool_t pool;		/**< pool to alloc packets from */

	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_bool_t lockless_tx;		/**< no locking for TX */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	uint8_t *mmio;			/**< MMIO region */

	int sockfd;			/**< control socket */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_thunderx_data_t;

static void thunderx_wait_link_up(pktio_entry_t *pktio_entry);
static int thunderx_close(pktio_entry_t *pktio_entry);

static int thunderx_mmio_register(pktio_ops_thunderx_data_t *pkt_thunderx,
				  uint64_t offset, uint64_t size)
{
	ODP_ASSERT(pkt_thunderx->mmio == NULL);

	pkt_thunderx->mmio =
	    mdev_region_mmap(&pkt_thunderx->mdev, offset, size);

	if (pkt_thunderx->mmio == MAP_FAILED) {
		ODP_ERR("Cannot mmap MMIO\n");
		return -1;
	}

	ODP_DBG("Register MMIO region: 0x%llx@%016llx\n", size, offset);

	return 0;
}

static int thunderx_rx_queue_register(pktio_ops_thunderx_data_t *pkt_thunderx,
				      uint64_t offset, uint64_t size)
{
	uint16_t rxq_idx = pkt_thunderx->capa.max_input_queues++;
	thunderx_rx_queue_t *rxq = &pkt_thunderx->rx_queues[rxq_idx];
	uint64_t doorbell_offset;
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(rxq_idx < ARRAY_SIZE(pkt_thunderx->rx_queues));

	odp_ticketlock_init(&rxq->lock);

	ret = ethtool_ringparam_get_fd(pkt_thunderx->sockfd,
				       pkt_thunderx->mdev.if_name, &ering);
	if (ret) {
		ODP_ERR("Cannot get queue length\n");
		return -1;
	}
	rxq->rx_queue_len = ering.rx_pending;

	ret = sysfs_attr_u64_get(&doorbell_offset,
				 "/sys/class/net/%s"
				 "/queues/rx-%u/thunderx/doorbell_offset",
				 pkt_thunderx->mdev.if_name, rxq_idx);
	if (ret) {
		ODP_ERR("Cannot get %s rx-%u doorbell_offset\n",
			pkt_thunderx->mdev.if_name, rxq_idx);
		return -1;
	}

	rxq->doorbell =
	    (odp_u32le_t *)(void *)(pkt_thunderx->mmio + doorbell_offset);

	ODP_ASSERT(rxq->rx_queue_len * sizeof(*rxq->rx_descs) <= size);

	rxq->rx_descs = mdev_region_mmap(&pkt_thunderx->mdev, offset, size);
	if (rxq->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
		return -1;
	}

	rxq->rx_data.size = rxq->rx_queue_len * THUNDERX_RX_BUF_SIZE;
	ret = mdev_dma_area_alloc(&pkt_thunderx->mdev, &rxq->rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}

	ODP_DBG("Register RX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX descriptors: %u\n", rxq->rx_queue_len);

	return 0;
}

static int thunderx_tx_queue_register(pktio_ops_thunderx_data_t *pkt_thunderx,
				      uint64_t offset, uint64_t size)
{
	uint16_t txq_idx = pkt_thunderx->capa.max_output_queues++;
	thunderx_tx_queue_t *txq = &pkt_thunderx->tx_queues[txq_idx];
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(txq_idx < ARRAY_SIZE(pkt_thunderx->tx_queues));

	odp_ticketlock_init(&txq->lock);

	ret = ethtool_ringparam_get_fd(pkt_thunderx->sockfd,
				       pkt_thunderx->mdev.if_name, &ering);
	if (ret) {
		ODP_ERR("Cannot get queue length\n");
		return -1;
	}
	txq->tx_queue_len = ering.tx_pending;

	txq->doorbell = (odp_u64le_t *)(void *)(pkt_thunderx->mmio +
					THUNDERX_TXQ_DOOR_OFFSET(txq_idx));

	ODP_ASSERT(txq->tx_queue_len * sizeof(*txq->tx_descs) == size);

	txq->tx_descs = mdev_region_mmap(&pkt_thunderx->mdev, offset, size);
	if (txq->tx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap TX queue\n");
		return -1;
	}

	txq->cidx = (odp_u64le_t *)(void *)(pkt_thunderx->mmio +
				    THUNDERX_TXQ_HEAD_OFFSET(txq_idx));

	txq->tx_data.size = txq->tx_queue_len * THUNDERX_TX_BUF_SIZE / 2;
	ret = mdev_dma_area_alloc(&pkt_thunderx->mdev, &txq->tx_data);
	if (ret) {
		ODP_ERR("Cannot allocate TX queue DMA area\n");
		return -1;
	}

	ODP_DBG("Register TX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    TX descriptors: %u\n", txq->tx_queue_len);

	return 0;
}

static int thunderx_region_info_cb(mdev_device_t *mdev,
				   struct vfio_region_info *region_info)
{
	pktio_ops_thunderx_data_t *pkt_thunderx =
	    odp_container_of(mdev, pktio_ops_thunderx_data_t, mdev);
	mdev_region_class_t class_info;

	if (vfio_get_region_cap_type(region_info, &class_info) < 0) {
		ODP_ERR("Cannot find class_info in region %u\n",
			region_info->index);
		return -1;
	}

	switch (class_info.type) {
	case VFIO_NET_MDEV_MMIO:
		return thunderx_mmio_register(pkt_thunderx,
					  region_info->offset,
					  region_info->size);

	case VFIO_NET_MDEV_RX_RING:
		return thunderx_rx_queue_register(pkt_thunderx,
					      region_info->offset,
					      region_info->size);

	case VFIO_NET_MDEV_TX_RING:
		return thunderx_tx_queue_register(pkt_thunderx,
					      region_info->offset,
					      region_info->size);

	default:
		ODP_ERR("Unexpected region %u (class %u:%u)\n",
			region_info->index, class_info.type,
			class_info.subtype);
		return -1;
	}
}

static int thunderx_open(odp_pktio_t id ODP_UNUSED,
			 pktio_entry_t *pktio_entry,
			 const char *resource, odp_pool_t pool)
{
	pktio_ops_thunderx_data_t *pkt_thunderx;
	int ret;

	ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	ODP_DBG("%s: probing resource %s\n", MODULE_NAME, resource);

	pkt_thunderx = ODP_OPS_DATA_ALLOC(sizeof(*pkt_thunderx));
	if (odp_unlikely(pkt_thunderx == NULL)) {
		ODP_ERR("Failed to allocate pktio_ops_thunderx_data_t struct");
		return -1;
	}
	pktio_entry->s.ops_data = pkt_thunderx;

	memset(pkt_thunderx, 0, sizeof(*pkt_thunderx));

	pkt_thunderx->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (pkt_thunderx->sockfd == -1) {
		ODP_ERR("Cannot get device control socket\n");
		goto out;
	}

	ret =
	    mdev_device_create(&pkt_thunderx->mdev, MODULE_NAME,
			       resource + strlen(NET_MDEV_PREFIX),
			       thunderx_region_info_cb);
	if (ret)
		goto out;

	pkt_thunderx->pool = pool;

	thunderx_wait_link_up(pktio_entry);

	ODP_DBG("%s: open %s is successful\n", MODULE_NAME,
		pkt_thunderx->mdev.if_name);

	return 0;

out:
	thunderx_close(pktio_entry);
	return -1;
}

static int thunderx_close(pktio_entry_t *pktio_entry)
{
	uint16_t i;

	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;

	ODP_DBG("%s: close %s\n", MODULE_NAME, pkt_thunderx->mdev.if_name);

	mdev_device_destroy(&pkt_thunderx->mdev);

	for (i = 0; i < pkt_thunderx->capa.max_input_queues; i++) {
		thunderx_rx_queue_t *rxq = &pkt_thunderx->rx_queues[i];

		if (rxq->rx_data.size)
			mdev_dma_area_free(&pkt_thunderx->mdev, &rxq->rx_data);
	}

	for (i = 0; i < pkt_thunderx->capa.max_output_queues; i++) {
		thunderx_tx_queue_t *txq = &pkt_thunderx->tx_queues[i];

		if (txq->tx_data.size)
			mdev_dma_area_free(&pkt_thunderx->mdev, &txq->tx_data);
	}

	if (pkt_thunderx->sockfd != -1)
		close(pkt_thunderx->sockfd);

	ODP_OPS_DATA_FREE(pkt_thunderx);

	return 0;
}

static int thunderx_recv(pktio_entry_t *pktio_entry, int rxq_idx,
			 odp_packet_t ODP_UNUSED pkt_table[],
			 int ODP_UNUSED num)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;
	thunderx_rx_queue_t *rxq = &pkt_thunderx->rx_queues[rxq_idx];
	int rx_pkts = 0;

	if (!pkt_thunderx->lockless_rx)
		odp_ticketlock_lock(&rxq->lock);

	if (!pkt_thunderx->lockless_rx)
		odp_ticketlock_unlock(&rxq->lock);

	return rx_pkts;
}

static int thunderx_send(pktio_entry_t *pktio_entry, int txq_idx,
			 const odp_packet_t pkt_table[], int num)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;
	thunderx_tx_queue_t *txq = &pkt_thunderx->tx_queues[txq_idx];
	uint16_t budget, tx_txds = 0;
	int tx_pkts = 0;

	if (!pkt_thunderx->lockless_tx)
		odp_ticketlock_lock(&txq->lock);

	/* Determine how many packets will fit in TX queue */
	budget = txq->tx_queue_len - 2;
	budget -= txq->pidx;
	budget += odp_le_to_cpu_64(*txq->cidx) >> 4;
	budget &= txq->tx_queue_len - 1;

	while (tx_txds < budget && tx_pkts < num) {
		uint16_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);
		uint32_t offset = (txq->pidx >> 1) * THUNDERX_TX_BUF_SIZE;

		thunderx_tx_desc_t *txd = &txq->tx_descs[txq->pidx];

		/* Skip undersized packets silently */
		if (odp_unlikely(pkt_len < THUNDERX_TX_PACKET_LEN_MIN)) {
			tx_pkts++;
			continue;
		}

		/* Skip oversized packets silently */
		if (odp_unlikely(pkt_len > THUNDERX_TX_BUF_SIZE)) {
			tx_pkts++;
			continue;
		}

		odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
				       (uint8_t *)txq->tx_data.vaddr + offset);

		/* "Header" descriptor */
		txd->qw0 =
		    odp_cpu_to_le_64(TXD_QW0_TYPE_V(TXD_TYPE_HEADER) |
				     TXD_QW0_SUBDESC_COUNT_V(1) |
				     TXD_QW0_SIZE_V(pkt_len));

		txd++;

		/* "Gather" descriptor */
		txd->qw0 =
		    odp_cpu_to_le_64(TXD_QW0_TYPE_V(TXD_TYPE_GATHER) |
				     TXD_QW0_SIZE_V(pkt_len));
		txd->qw1 =
		    odp_cpu_to_le_64(TXD_QW1_ADDR_V(txq->tx_data.iova +
						    offset));

		txq->pidx += 2;
		if (odp_unlikely(txq->pidx >= txq->tx_queue_len))
			txq->pidx = 0;

		tx_txds += 2;
		tx_pkts++;
	}

	/*
	 * Ring the doorbell
	 */
	txq->tx_txds_acc += tx_txds;
	if (txq->tx_txds_acc > 128) {
		odpdrv_mmio_u64le_write(128, txq->doorbell);
		txq->tx_txds_acc -= 128;
	}

	if (!pkt_thunderx->lockless_tx)
		odp_ticketlock_unlock(&txq->lock);

	odp_packet_free_multi(pkt_table, tx_pkts);

	return tx_pkts;
}

static int thunderx_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;

	return link_status_fd(pkt_thunderx->sockfd, pkt_thunderx->mdev.if_name);
}

static void thunderx_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!thunderx_link_status(pktio_entry))
		sleep(1);
}

static int thunderx_capability(pktio_entry_t *pktio_entry,
			       odp_pktio_capability_t *capa)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;

	*capa = pkt_thunderx->capa;
	return 0;
}

static int thunderx_input_queues_config(pktio_entry_t *pktio_entry,
					const odp_pktin_queue_param_t *p)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pkt_thunderx->lockless_rx = 1;
	else
		pkt_thunderx->lockless_rx = 0;

	return 0;
}

static int thunderx_output_queues_config(pktio_entry_t *pktio_entry,
					 const odp_pktout_queue_param_t *p)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pkt_thunderx->lockless_tx = 1;
	else
		pkt_thunderx->lockless_tx = 0;

	return 0;
}

static int thunderx_mac_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;

	if (mac_addr_get_fd(pkt_thunderx->sockfd, pkt_thunderx->mdev.if_name,
			    mac_addr) < 0)
		return -1;

	return ETH_ALEN;
}

static int thunderx_init_global(void)
{
	ODP_PRINT("PKTIO: initialized " MODULE_NAME " interface\n");
	return 0;
}

static pktio_ops_module_t thunderx_pktio_ops = {
	.base = {
		 .name = MODULE_NAME,
		 .init_global = thunderx_init_global,
	},

	.open = thunderx_open,
	.close = thunderx_close,

	.recv = thunderx_recv,
	.send = thunderx_send,

	.link_status = thunderx_link_status,

	.capability = thunderx_capability,

	.mac_get = thunderx_mac_get,

	.input_queues_config = thunderx_input_queues_config,
	.output_queues_config = thunderx_output_queues_config,
};

/** thunderx module entry point */
ODP_MODULE_CONSTRUCTOR(netmap_pktio_ops)
{
	odp_module_constructor(&thunderx_pktio_ops);

	odp_subsystem_register_module(pktio_ops, &thunderx_pktio_ops);
}

/*
 * Temporary variable to enable link this module,
 * will remove in Makefile scheme changes.
 */
int enable_link_thunderx_pktio_ops;

#endif /* _ODP_MDEV */
