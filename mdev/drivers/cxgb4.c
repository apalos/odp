#include "config.h"

#include <odp_posix_extensions.h>

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/types.h>

#include <odp/drv/byteorder.h>
#include <odp/api/hints.h>
#include <odp/drv/hints.h>
#include <odp/drv/align.h>

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/packet.h>

#include <odp_packet_io_internal.h>

#include <protocols/eth.h>

#include <drivers/driver_ops.h>
#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>
#include <sysfs_parse.h>
#include <eth_stats.h>

#include <uapi/net_mdev.h>

#define MODULE_NAME "cxgb4"

/* Common code. TODO: relocate */
#if 1
#define barrier() __asm__ __volatile__("": : :"memory")
#define dma_wmb() barrier()
#define dma_rmb() barrier()
typedef unsigned long dma_addr_t;
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif


/* RX queue definitions */
#define CXGB4_RX_QUEUE_NUM_MAX 32

/** RX descriptor */
typedef struct {
	uint32_t padding[12];

	odpdrv_u32be_t hdrbuflen_pidx;
#define RX_DESC_NEW_BUF_FLAG	(1U << 31)
	odpdrv_u32be_t pldbuflen_qid;
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
		odpdrv_u64be_t last_flit;
	};
} cxgb4_rx_desc_t;

#define RX_DESC_TO_GEN(rxd) \
	(((rxd)->type_gen >> RX_DESC_GEN_SHIFT) & RX_DESC_GEN_MASK)
#define RX_DESC_TO_TYPE(rxd) \
	(((rxd)->type_gen >> RX_DESC_TYPE_SHIFT) & RX_DESC_TYPE_MASK)

/** RX queue data */
typedef struct {
	uint32_t gen:1;			/**< RX queue generation */

	uint32_t rx_data_size;		/**< RX packet payload area size */
	uint8_t *rx_data_base;		/**< RX packet payload area VA */
	uint64_t rx_iova_base;		/**< RX packet payload area IOVA */

	cxgb4_rx_desc_t *desc;		/**< RX queue base */

	odpdrv_u64be_t *free_list;	/**< Free list base */

	odpdrv_u32be_t *doorbell;	/**< Free list refill doorbell */
	uint32_t qhandle;		/**< 'Key' to the doorbell */

	uint16_t rx_queue_len;		/**< Number of RX desc entries */
	uint16_t rx_next;		/**< Next RX desc to handle */

	uint8_t free_list_len;		/**< Number of free list entries */
	uint8_t commit_pending;		/**< Free list entries pending commit */

	uint8_t cidx;			/**< Free list consumer index */
	uint8_t pidx;			/**< Free list producer index */

	uint32_t offset;		/**< Offset into last free fragment */
} cxgb4_rx_queue_t ODPDRV_ALIGNED_CACHE;

/* TX queue definitions */
#define CXGB4_TX_QUEUE_NUM_MAX 32

/** TX queue data */
typedef struct {
} cxgb4_tx_queue_t ODPDRV_ALIGNED_CACHE;

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
	odp_bool_t lockless_tx;		/**< no locking for TX */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	void *mmio;			/**< BAR0 mmap */
	size_t mmio_len;		/**< MMIO mmap'ed region length */

	mdev_device_t mdev;		/**< Common mdev data */

	char if_name[IF_NAMESIZE];	/**< Interface name */
} pktio_ops_cxgb4_data_t;

static void cxgb4_rx_refill(cxgb4_rx_queue_t *rxq, uint8_t num);
static void cxgb4_wait_link_up(pktio_entry_t *pktio_entry);
static int cxgb4_close(pktio_entry_t *pktio_entry);

static int cxgb4_open(odp_pktio_t id ODP_UNUSED,
		       pktio_entry_t * pktio_entry,
		       const char *resource, odp_pool_t pool)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);
	int ret;

	// ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	/* Init pktio entry */
	memset(pkt_cxgb4, 0, sizeof(*pkt_cxgb4));
	strncpy(pkt_cxgb4->if_name, resource + strlen(NET_MDEV_PREFIX),
		sizeof(pkt_cxgb4->if_name - 1));

	printf("%s: open %s\n", MODULE_NAME, pkt_cxgb4->if_name);

	ret = mdev_device_create(&pkt_cxgb4->mdev, MODULE_NAME, pkt_cxgb4->if_name);
	if (ret)
		goto out;

	pkt_cxgb4->pool = pool;

	for (uint32_t i = 0; i < ARRAY_SIZE(pkt_cxgb4->rx_locks); i++)
		odp_ticketlock_init(&pkt_cxgb4->rx_locks[i]);
	for (uint32_t i = 0; i < ARRAY_SIZE(pkt_cxgb4->tx_locks); i++)
		odp_ticketlock_init(&pkt_cxgb4->tx_locks[i]);

	for (uint32_t i = 0; i < ARRAY_SIZE(pkt_cxgb4->rx_queues); i++) {
		cxgb4_rx_queue_t *rxq = &pkt_cxgb4->rx_queues[i];

		/*
		 * Leave 1 HW block (8 entries) unpopulated,
		 * otherwise HW will think the free list is empty.
		 */
		cxgb4_rx_refill(rxq, rxq->free_list_len - 8);
	}

	cxgb4_wait_link_up(pktio_entry);

	printf("%s: open %s is successful\n", MODULE_NAME, pkt_cxgb4->if_name);

	return 0;

out:
	cxgb4_close(pktio_entry);

	return -1;
}


static int cxgb4_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);

	printf("%s: close %s\n", MODULE_NAME, pkt_cxgb4->if_name);

	mdev_device_destroy(&pkt_cxgb4->mdev);

	if (pkt_cxgb4->mmio)
		munmap(pkt_cxgb4->mmio, pkt_cxgb4->mmio_len);

	return 0;
}

static void cxgb4_rx_refill(cxgb4_rx_queue_t *rxq, uint8_t num)
{
	rxq->commit_pending += num;

	while (num) {
		uint64_t iova = rxq->rx_iova_base + rxq->pidx * ODP_PAGE_SIZE;

		rxq->free_list[rxq->pidx] = odpdrv_cpu_to_be_64(iova);

		rxq->pidx++;
		if (odp_unlikely(rxq->pidx >= rxq->free_list_len))
			rxq->pidx = 0;

		num--;
	}

	/* We commit free list entries to HW in packs of 8 */
	if (rxq->commit_pending >= 8) {
		uint32_t val = rxq->qhandle | (rxq->commit_pending / 8);

		dma_wmb();
		io_write32(odpdrv_cpu_to_be_32(val), rxq->doorbell);

		rxq->commit_pending &= 7;
	}
}

static int cxgb4_recv(pktio_entry_t * pktio_entry,
		      int index, odp_packet_t pkt_table[], int num)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);
	cxgb4_rx_queue_t *rxq = &pkt_cxgb4->rx_queues[index];
	uint16_t refill_count = 0;
	int rx_pkts = 0;

	if (!pkt_cxgb4->lockless_rx)
		odp_ticketlock_lock(&pkt_cxgb4->rx_locks[index]);

	while (num) {
		volatile cxgb4_rx_desc_t *rxd = &rxq->desc[rxq->rx_next];
		odp_packet_t pkt;
		uint32_t pkt_len, offset;
		uint8_t type;
		int ret;

		if (RX_DESC_TO_GEN(rxd) != rxq->gen)
			break;

		type = RX_DESC_TO_TYPE(rxd);

		if (odp_unlikely(type != RX_DESC_TYPE_FLBUF_X)) {
			// ODP_ERR("Invalid rxd type %u\n", type);
			printf("Invalid rxd type %u, skipping\n", type);

			rxq->rx_next++;
			if (odp_unlikely(rxq->rx_next >= rxq->rx_queue_len))
				rxq->rx_next = 0;

			continue;
		}

		pkt_len = odpdrv_be_to_cpu_32(rxd->pldbuflen_qid);

		/*
		 * HW skips trailing area in current RX buffer and starts in the
		 * next one from the beginning.
		 */
		if (pkt_len & RX_DESC_NEW_BUF_FLAG) {
			rxq->offset = 0;

			rxq->cidx++;
			if (odp_unlikely(rxq->cidx >= rxq->free_list_len))
				rxq->cidx = 0;

			pkt_len ^= RX_DESC_NEW_BUF_FLAG;

			refill_count++;
		}

		/*
		 * We can't stop from now on. In case of failure -- update RX
		 * queue and free list properly and drop the packet.
		 */
		ret = 0;

		pkt = odp_packet_alloc(pkt_cxgb4->pool, pkt_len);
		if (odp_unlikely(pkt == ODP_PACKET_INVALID))
			ret = -1;

		offset = 0; /* TODO: any better name for this */
		while (offset <= pkt_len) {
			void *from =
			    rxq->rx_data_base + rxq->cidx * ODP_PAGE_SIZE +
			    rxq->offset;
			uint32_t len =
			    MIN(pkt_len - offset, ODP_PAGE_SIZE - rxq->offset);

			if (!ret)
				ret =
				    odp_packet_copy_from_mem(pkt, offset, len,
							     from);

			offset += len;

			rxq->cidx++;
			if (odp_unlikely(rxq->cidx >= rxq->free_list_len))
				rxq->cidx = 0;

			rxq->offset = 0;
		}

		/* TODO: fl_align shall be in capabilities */
		rxq->offset = ROUNDUP_ALIGN(rxq->offset, 64);

		rxq->rx_next++;
		if (odp_unlikely(rxq->rx_next >= rxq->rx_queue_len)) {
			rxq->rx_next = 0;
			rxq->gen ^= 1;
		}

		if (odp_likely(!ret)) {
			odp_packet_hdr_t *pkt_hdr;

			pkt_hdr = odp_packet_hdr(pkt);
			pkt_hdr->input = pktio_entry->s.handle;

			pkt_table[rx_pkts] = pkt;
			rx_pkts++;
		}

		num--;
	}

	if (refill_count)
		cxgb4_rx_refill(rxq, refill_count);

	if (!pkt_cxgb4->lockless_rx)
		odp_ticketlock_unlock(&pkt_cxgb4->rx_locks[index]);

	return rx_pkts;
}

static int cxgb4_send(pktio_entry_t * pktio_entry ODP_UNUSED,
		       int index ODP_UNUSED,
		       const odp_packet_t pkt_table[] ODP_UNUSED,
		       int num ODP_UNUSED)
{
	return 0;
}

static int cxgb4_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);

	return mdev_get_iff_link(pkt_cxgb4->if_name);
}

/* TODO: move to common code */
static void cxgb4_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!cxgb4_link_status(pktio_entry)) {
		sleep(1);
	}
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
};

/** cxgb4 module entry point */
static void ODPDRV_CONSTRUCTOR cxgb4_module_init(void)
{
	odp_module_constructor(&cxgb4_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &cxgb4_pktio_ops);
}
