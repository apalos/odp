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
#endif

/* TX ring definitions */
typedef struct {
} cxgb4_tx_desc_t;

/* RX ring definitions */
typedef struct {
} cxgb4_rx_desc_t;

/** Packet socket using mediated cxgb4 device */
typedef struct {
	/* TODO: cache align everything when we have profiling information */
	odp_pool_t pool;		/**< pool to alloc packets from */

	void *mmio;			/**< BAR0 mmap */

	/* RX ring hot data */
	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_ticketlock_t rx_lock;	/**< RX ring lock */
	cxgb4_rx_desc_t *rx_ring;	/**< RX ring mmap */
	struct iomem rx_data;		/**< RX packet payload mmap */
	uint16_t rx_next;		/**< next entry in RX ring to use */

	/* TX ring hot data */
	odp_bool_t lockless_tx;		/**< no locking for TX */
	odp_ticketlock_t tx_lock;	/**< TX ring lock */
	cxgb4_tx_desc_t *tx_ring;	/**< TX ring mmap */
	struct iomem tx_data;		/**< TX packet payload mmap */
	uint16_t tx_next;		/**< next entry in TX ring to use */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	int device;			/**< VFIO device */
	int group;			/**< VFIO group */

	size_t mmio_len;		/**< MMIO mmap'ed region length */
	size_t rx_ring_len;		/**< Rx ring mmap'ed region length */
	size_t tx_ring_len;		/**< Tx ring mmap'ed region length */

	char ifname[IFNAMSIZ + 1];	/**< Interface name */
} pktio_ops_cxgb4_data_t;

static pktio_ops_module_t cxgb4_pktio_ops;

#if 0
static void cxgb4_rx_refill(pktio_ops_cxgb4_data_t *pkt_cxgb4,
			     uint16_t from, uint16_t num);
#endif

static void cxgb4_wait_link_up(pktio_entry_t *pktio_entry);

static int cxgb4_open(odp_pktio_t id ODP_UNUSED,
		       pktio_entry_t * pktio_entry,
		       const char *netdev, odp_pool_t pool)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	int container = -1, group = -1, device = -1;
	int ret;
	void *iobase, *iocur;
	pktio_ops_cxgb4_data_t *pkt_cxgb4 = odp_ops_data(pktio_entry, cxgb4);
	char group_uuid[64]; /* 37 should be enough */
	int group_id;

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

	pkt_cxgb4->capa.max_input_queues = 1;
	pkt_cxgb4->capa.max_output_queues = 1;

	odp_ticketlock_init(&pkt_cxgb4->rx_lock);
	odp_ticketlock_init(&pkt_cxgb4->tx_lock);

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

	// cxgb4_rx_refill(pkt_cxgb4, 0, ???);

	cxgb4_wait_link_up(pktio_entry);

	printf("%s: probing is complete\n", __func__);

	return 0;
out:
	if (group > 0)
		close(group);
	if (pkt_cxgb4->tx_data.vaddr)
		iomem_free_dma(device, &pkt_cxgb4->tx_data);
	if (pkt_cxgb4->rx_data.vaddr)
		iomem_free_dma(device, &pkt_cxgb4->rx_data);
	if (pkt_cxgb4->tx_ring)
		munmap(pkt_cxgb4->tx_ring, pkt_cxgb4->tx_ring_len);
	if (pkt_cxgb4->rx_ring)
		munmap(pkt_cxgb4->rx_ring, pkt_cxgb4->rx_ring_len);
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
	if (pkt_cxgb4->tx_data.vaddr)
		iomem_free_dma(pkt_cxgb4->device, &pkt_cxgb4->tx_data);
	if (pkt_cxgb4->rx_data.vaddr)
		iomem_free_dma(pkt_cxgb4->device, &pkt_cxgb4->rx_data);
	if (pkt_cxgb4->tx_ring)
		munmap(pkt_cxgb4->tx_ring, pkt_cxgb4->tx_ring_len);
	if (pkt_cxgb4->rx_ring)
		munmap(pkt_cxgb4->rx_ring, pkt_cxgb4->rx_ring_len);
	if (pkt_cxgb4->mmio)
		munmap(pkt_cxgb4->mmio, pkt_cxgb4->mmio_len);

	return 0;
}

#if 0
static void cxgb4_rx_refill(pktio_ops_cxgb4_data_t * pkt_cxgb4,
			    uint16_t from, uint16_t num)
{
}
#endif

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
