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
#include <pktio/uapi_net_mdev.h>

#define MODULE_NAME "thunder-nicvf"

/* RX queue definitions */
#define THUNDERX_RX_QUEUE_NUM_MAX	8UL

#define THUNDERX_RXQ_PIDX_OFFSET(rxq_idx)	(0x010430UL + ((rxq_idx) << 18))
#define THUNDERX_RXQ_DOOR_OFFSET(rxq_idx)	(0x010438UL + ((rxq_idx) << 18))

/** RX descriptor */
typedef struct {
	odp_u64le_t data[64];
} thunderx_rx_desc_t;

/** RX queue data */
typedef struct ODP_ALIGNED_CACHE {
	thunderx_rx_desc_t *rx_descs;	/**< RX queue base */
	odp_u64le_t *doorbell;		/**< RX queue doorbell */
	uint16_t rx_rxds_acc;		/**< RX descriptor accumulator */

	uint16_t cidx;			/**< Next RX desc to process */
	odp_u64le_t *pidx;		/**< RX queue producer index */

	uint16_t rx_queue_len;		/**< Number of RX desc entries */

	odp_ticketlock_t lock;		/**< RX queue lock */
} thunderx_rx_queue_t;

/* TX queue definitions */
#define THUNDERX_TX_QUEUE_NUM_MAX	8UL
#define THUNDERX_TX_BUF_SIZE		2048UL
#define THUNDERX_TX_PACKET_LEN_MIN	ETH_ALEN

#define THUNDERX_TXQ_CIDX_OFFSET(txq_idx) (0x010828UL + ((txq_idx) << 18))
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

/* RX pool definitions */
#define THUNDERX_RX_BUF_SIZE		2048UL
#define THUNDERX_RX_POOL_DOOR_OFFSET	0x010C38UL
#define THUNDERX_RX_POOL_LEN_DEFAULT	8192UL

typedef struct ODP_ALIGNED_CACHE {
	odp_u64le_t *bufs;		/**< RX buffers */
	odp_u64le_t *doorbell;		/**< RX pool doorbell */
	uint16_t pidx;			/**< Next RX buf to insert */
	uint16_t len;			/**< RX pool length */
	mdev_dma_area_t rx_data;	/**< RX packet payload area */
	odp_ticketlock_t lock;		/**< RX pool lock */
} thunderx_rx_pool_t;

/** Packet socket using mediated thunderx device */
typedef struct {
	/** RX queue hot data */
	thunderx_rx_queue_t rx_queues[THUNDERX_RX_QUEUE_NUM_MAX];

	/** TX queue hot data */
	thunderx_tx_queue_t tx_queues[THUNDERX_TX_QUEUE_NUM_MAX];

	/** RX pool hot data */
	thunderx_rx_pool_t rx_pool;

	odp_pool_t pool;		/**< pool to alloc packets from */

	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_bool_t lockless_tx;		/**< no locking for TX */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	uint8_t *mmio;			/**< MMIO region */

	int sockfd;			/**< control socket */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_thunderx_data_t;

static void thunderx_rx_refill(pktio_ops_thunderx_data_t *pkt_thunderx,
			       uint16_t num);
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

	rxq->doorbell =
	    (odp_u64le_t *)(void *)(pkt_thunderx->mmio +
				    THUNDERX_RXQ_DOOR_OFFSET(rxq_idx));
	rxq->pidx =
	    (odp_u64le_t *)(void *)(pkt_thunderx->mmio +
			    	    THUNDERX_RXQ_PIDX_OFFSET(rxq_idx));

	ODP_ASSERT(rxq->rx_queue_len * sizeof(*rxq->rx_descs) == size);

	rxq->rx_descs = mdev_region_mmap(&pkt_thunderx->mdev, offset, size);
	if (rxq->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
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
				    THUNDERX_TXQ_CIDX_OFFSET(txq_idx));

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

static int thunderx_rx_pool_register(pktio_ops_thunderx_data_t *pkt_thunderx,
				     uint64_t offset, uint64_t size)
{
	thunderx_rx_pool_t *rx_pool = &pkt_thunderx->rx_pool;
	int ret;

	ODP_ASSERT(rx_pool->bufs == NULL);
	ODP_ASSERT(THUNDERX_RX_POOL_LEN_DEFAULT * sizeof(*rx_pool->bufs) ==
		   size);

	odp_ticketlock_init(&rx_pool->lock);

	rx_pool->bufs = mdev_region_mmap(&pkt_thunderx->mdev, offset, size);
	if (rx_pool->bufs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX pool\n");
		return -1;
	}

	rx_pool->len = THUNDERX_RX_POOL_LEN_DEFAULT;

	rx_pool->rx_data.size = rx_pool->len * THUNDERX_RX_BUF_SIZE;
	ret = mdev_dma_area_alloc(&pkt_thunderx->mdev, &rx_pool->rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}

	rx_pool->doorbell = (odp_u64le_t *)(void *)(pkt_thunderx->mmio +
		THUNDERX_RX_POOL_DOOR_OFFSET);

	/* Need 1 desc gap to keep tail from touching head */
	thunderx_rx_refill(pkt_thunderx, rx_pool->len - 1);

	ODP_DBG("Register RX pool region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX buffers: %u\n", rx_pool->len);

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

	case VFIO_NET_MDEV_RX_BUFFER_POOL:
		return thunderx_rx_pool_register(pkt_thunderx,
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

	for (i = 0; i < pkt_thunderx->capa.max_output_queues; i++) {
		thunderx_tx_queue_t *txq = &pkt_thunderx->tx_queues[i];

		if (txq->tx_data.size)
			mdev_dma_area_free(&pkt_thunderx->mdev, &txq->tx_data);
	}

	if (pkt_thunderx->rx_pool.rx_data.size)
		mdev_dma_area_free(&pkt_thunderx->mdev,
				   &pkt_thunderx->rx_pool.rx_data);

	if (pkt_thunderx->sockfd != -1)
		close(pkt_thunderx->sockfd);

	ODP_OPS_DATA_FREE(pkt_thunderx);

	return 0;
}

static void thunderx_rx_refill(pktio_ops_thunderx_data_t *pkt_thunderx,
			       uint16_t num)
{
	thunderx_rx_pool_t *rx_pool = &pkt_thunderx->rx_pool;
	uint16_t done = 0;

	odp_ticketlock_lock(&rx_pool->lock);

	while (done < num) {
		uint64_t iova =
		    rx_pool->rx_data.iova +
		    rx_pool->pidx * THUNDERX_RX_BUF_SIZE;

		rx_pool->bufs[rx_pool->pidx] = odp_cpu_to_le_64(iova);

		rx_pool->pidx++;
		if (rx_pool->pidx >= rx_pool->len)
			rx_pool->pidx = 0;

		done++;
	}

	/* Ring the doorbell */
	odpdrv_mmio_u64le_write(num, rx_pool->doorbell);

	odp_ticketlock_unlock(&rx_pool->lock);
}

static int thunderx_recv(pktio_entry_t *pktio_entry, int rxq_idx,
			 odp_packet_t pkt_table[], int num)
{
	pktio_ops_thunderx_data_t *pkt_thunderx = pktio_entry->s.ops_data;
	thunderx_rx_queue_t *rxq = &pkt_thunderx->rx_queues[rxq_idx];
	uint16_t rx_rxds = 0;
	uint16_t budget;
	int rx_pkts = 0;
	int ret;

	if (!pkt_thunderx->lockless_rx)
		odp_ticketlock_lock(&rxq->lock);

	/*
	 * Determine how many packets are available in RX queue:
	 *     (Write_index - Read_index) modulo RX queue size
	 */
	budget = odpdrv_mmio_u64le_read(rxq->pidx) >> 9;
	budget -= rxq->cidx;
	budget &= rxq->rx_queue_len - 1;

	if (budget > num)
		budget = num;

	ret = odp_packet_alloc_multi(pkt_thunderx->pool, THUNDERX_RX_BUF_SIZE,
				     pkt_table, budget);
	budget = (ret > 0) ? ret : 0;

	while (rx_rxds < budget) {
		thunderx_rx_desc_t *rxd = &rxq->rx_descs[rxq->cidx];
		odp_packet_hdr_t *pkt_hdr;
		odp_packet_t pkt = pkt_table[rx_pkts];
		odp_u16le_t *seg_len = (odp_u16le_t *)&rxd->data[3];
		odp_u64le_t *seg_iova = (odp_u64le_t *)&rxd->data[7];
		uint16_t pkt_len;
		uint8_t *pkt_payload;

		pkt_len = odp_le_to_cpu_16(seg_len[0]);
		pkt_payload =
		    (uint8_t *)odp_le_to_cpu_64(seg_iova[0]) +
		    (pkt_thunderx->rx_pool.rx_data.vaddr -
		    pkt_thunderx->rx_pool.rx_data.iova);

		ret = odp_packet_copy_from_mem(pkt, 0, pkt_len, pkt_payload);

		if (odp_unlikely(ret))
			break;

		pkt_hdr = odp_packet_hdr(pkt);
		pkt_hdr->input = pktio_entry->s.handle;

		rxq->cidx++;
		if (odp_unlikely(rxq->cidx >= rxq->rx_queue_len))
			rxq->cidx = 0;

		rx_pkts++;
		rx_rxds++;
	}

	/*
	 * Ring the doorbell
	 */
	rxq->rx_rxds_acc += rx_rxds;
	if (rxq->rx_rxds_acc >= (rxq->rx_queue_len >> 2)) {
		odpdrv_mmio_u64le_write(rxq->rx_rxds_acc, rxq->doorbell);
		thunderx_rx_refill(pkt_thunderx, rxq->rx_rxds_acc);
		rxq->rx_rxds_acc = 0;
	}

	if (!pkt_thunderx->lockless_rx)
		odp_ticketlock_unlock(&rxq->lock);

	if (rx_pkts < budget)
		odp_packet_free_multi(pkt_table + rx_pkts, budget - rx_pkts);

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
