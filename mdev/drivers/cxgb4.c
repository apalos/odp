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

/* Common code. TODO: relocate */
#if 1
#define barrier() __asm__ __volatile__("": : :"memory")
#define dma_wmb() barrier()
#define dma_rmb() barrier()
typedef unsigned long dma_addr_t;
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
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
#define RX_DESC_GEN_MASK	(1U << 7)
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

/** RX queue data */
typedef struct {
	cxgb4_rx_desc_t *desc;		/**< RX queue base */

	struct iomem rx_data;		/**< RX packet payload mmap */

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
} cxgb4_rx_queue_t ODPDRV_ALIGNED(_ODP_CACHE_LINE_SIZE);

/* TX queue definitions */
#define CXGB4_TX_QUEUE_NUM_MAX 32

/** TX queue data */
typedef struct {
} cxgb4_tx_queue_t ODPDRV_ALIGNED(_ODP_CACHE_LINE_SIZE);

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

	int device;			/**< VFIO device */
	int group;			/**< VFIO group */

	void *mmio;			/**< BAR0 mmap */
	size_t mmio_len;		/**< MMIO mmap'ed region length */

	char ifname[IFNAMSIZ + 1];	/**< Interface name */
} pktio_ops_cxgb4_data_t;

static pktio_ops_module_t cxgb4_pktio_ops;

static void cxgb4_rx_refill(cxgb4_rx_queue_t *rxq, uint8_t num);

static void cxgb4_wait_link_up(pktio_entry_t *pktio_entry);

static int cxgb4_open(odp_pktio_t id ODP_UNUSED,
		       pktio_entry_t * pktio_entry,
		       const char *netdev, odp_pool_t pool)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	int container = -1, group = -1, device = -1;
	void *iobase, *iocur ODP_UNUSED;
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);
	char group_uuid[64]; /* 37 should be enough */
	int group_id;
	uint32_t i;

	printf("%s: probing %s\n", __func__, netdev);

	/* Init pktio entry */
	memset(pkt_cxgb4, 0, sizeof(*pkt_cxgb4));
	memset(group_uuid, 0, sizeof(group_uuid));

	if (pool == ODP_POOL_INVALID)
		return -EINVAL;

	pkt_cxgb4->pool = pool;

	group_id =
	    mdev_sysfs_discover(netdev, cxgb4_pktio_ops.base.name, group_uuid,
				sizeof(group_uuid));
	if (group_id < 0)
		return -EINVAL;

	strncpy(pkt_cxgb4->ifname, netdev + strlen(NET_MDEV_MATCH), IFNAMSIZ);

	for (i = 0; i < ARRAY_SIZE(pkt_cxgb4->rx_locks); i++)
		odp_ticketlock_init(&pkt_cxgb4->rx_locks[i]);
	for (i = 0; i < ARRAY_SIZE(pkt_cxgb4->tx_locks); i++)
		odp_ticketlock_init(&pkt_cxgb4->tx_locks[i]);

	// TODO: these shall be filled in during VFIO region info parsing
	// pkt_cxgb4->capa.max_input_queues = 1;
	// pkt_cxgb4->capa.max_output_queues = 1;

	/* FIXME iobase and container(probably) has to be done globally and not per driver */
	iobase = iomem_init();
	if (!iobase)
		return -ENOMEM;
	iocur = iobase;
	container = get_container();
	if (container < 0)
		goto out;

	group = get_group(group_id);
	if (group < 0)
		goto out;
	pkt_cxgb4->group = group;

	device = vfio_init_dev(group, container, &group_status, &iommu_info,
			       &device_info, group_uuid);

	if (device < 0)
		goto out;
	pkt_cxgb4->device = device;

	/* Init device and mmaps */
	pkt_cxgb4->mmio = vfio_mmap_region(device, 0, &pkt_cxgb4->mmio_len);
	if (!pkt_cxgb4->mmio) {
		printf("Cannot map MMIO\n");
		goto out;
	}

#if 0
	pkt_cxgb4->rx_ring = vfio_mmap_region(device, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_RX_REGION_INDEX,
					      &pkt_cxgb4->rx_ring_len);
	if (!pkt_cxgb4->rx_ring) {
		printf("Cannot map RxRing\n");
		goto out;
	}
	pkt_cxgb4->tx_ring = vfio_mmap_region(device, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_TX_REGION_INDEX,
					      &pkt_cxgb4->tx_ring_len);
	if (!pkt_cxgb4->tx_ring) {
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
	pkt_cxgb4->rx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(device, &iocur, &pkt_cxgb4->rx_data);
	if (ret)
		goto out;

	pkt_cxgb4->tx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(device, &iocur, &pkt_cxgb4->tx_data);
	if (ret)
		goto out;
#endif

	for (i = 0; i < ARRAY_SIZE(pkt_cxgb4->rx_queues); i++) {
		cxgb4_rx_queue_t *rxq = &pkt_cxgb4->rx_queues[i];

		/*
		 * Leave 1 HW block (8 entries) unpopulated,
		 * otherwise HW will think the free list is empty.
		 */
		cxgb4_rx_refill(rxq, rxq->free_list_len - 8);
	}

	cxgb4_wait_link_up(pktio_entry);

	printf("%s: probing is complete\n", __func__);

	return 0;
out:
	if (group > 0)
		close(group);
#if 0
	if (pkt_cxgb4->tx_data.vaddr)
		iomem_free_dma(device, &pkt_cxgb4->tx_data);
	if (pkt_cxgb4->rx_data.vaddr)
		iomem_free_dma(device, &pkt_cxgb4->rx_data);
	if (pkt_cxgb4->tx_ring)
		munmap(pkt_cxgb4->tx_ring, pkt_cxgb4->tx_ring_len);
	if (pkt_cxgb4->rx_ring)
		munmap(pkt_cxgb4->rx_ring, pkt_cxgb4->rx_ring_len);
#endif
	if (pkt_cxgb4->mmio)
		munmap(pkt_cxgb4->mmio, pkt_cxgb4->mmio_len);
	if (container > 0)
		close(container);
	if (iobase)
		iomem_free(iobase);

	return -1;
}


static int cxgb4_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);

	if (pkt_cxgb4->group > 0)
		close(pkt_cxgb4->group);
#if 0
	if (pkt_cxgb4->tx_data.vaddr)
		iomem_free_dma(pkt_cxgb4->device, &pkt_cxgb4->tx_data);
	if (pkt_cxgb4->rx_data.vaddr)
		iomem_free_dma(pkt_cxgb4->device, &pkt_cxgb4->rx_data);
	if (pkt_cxgb4->tx_ring)
		munmap(pkt_cxgb4->tx_ring, pkt_cxgb4->tx_ring_len);
	if (pkt_cxgb4->rx_ring)
		munmap(pkt_cxgb4->rx_ring, pkt_cxgb4->rx_ring_len);
#endif
	if (pkt_cxgb4->mmio)
		munmap(pkt_cxgb4->mmio, pkt_cxgb4->mmio_len);

	return 0;
}

static void cxgb4_rx_refill(cxgb4_rx_queue_t *rxq, uint8_t num)
{
	rxq->commit_pending += num;

	while (num) {
		uint64_t iova = rxq->rx_data.iova + rxq->pidx * ODP_PAGE_SIZE;

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
		io_write32(odp_cpu_to_be_32(val), rxq->doorbell);

		rxq->commit_pending &= 7;
	}
}

static int cxgb4_recv(pktio_entry_t * pktio_entry ODP_UNUSED,
		       int index ODP_UNUSED, odp_packet_t pkt_table[] ODP_UNUSED,
		       int num ODP_UNUSED)
{
	return 0;
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

	return mdev_get_iff_link(pkt_cxgb4->ifname);
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
		 .name = "cxgb4",
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
