/*
 * FIXME: add a macro to increment ring index module ring size.
 * FIXME: support variable ring size.
 */

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

#include <uapi/net_mdev.h>

/* Common code. TODO: relocate */
#if 1
#define barrier() __asm__ __volatile__("": : :"memory")
#define dma_wmb() barrier()
#define dma_rmb() barrier()
typedef unsigned long dma_addr_t;
#endif

/* TX ring definitions */
#define E1000E_TX_RING_SIZE_DEFAULT 256
#define E1000E_TX_RING_SIZE_MIN 64
#define E1000E_TX_RING_SIZE_MAX 4096

#define E1000_TDH_OFFSET 0x03810UL
#define E1000_TDT_OFFSET 0x03818UL

#define E1000E_TX_BUF_SIZE 2048U

typedef struct {
	odpdrv_u64le_t buffer_addr;		/* Address of the descriptor's data buffer */
	union {
#define E1000_TXD_CMD_EOP	0x01000000	/* End of Packet */
#define E1000_TXD_CMD_IFCS	0x02000000	/* Insert FCS (Ethernet CRC) */

		odpdrv_u32le_t data;
		struct {
			odpdrv_u16le_t length;	/* Data buffer length */
			uint8_t cso;		/* Checksum offset */
			uint8_t cmd;		/* Descriptor control */
		} flags;
	} lower;
	union {
		odpdrv_u32le_t data;
		struct {
			uint8_t status;		/* Descriptor status */
			uint8_t css;		/* Checksum start */
			odpdrv_u16le_t special;
		} fields;
	} upper;
} e1000e_tx_desc_t;

/* RX ring definitions */
#define E1000E_RX_RING_SIZE_DEFAULT 256
#define E1000E_RX_RING_SIZE_MIN 64
#define E1000E_RX_RING_SIZE_MAX 4096

#define E1000_RDH_OFFSET 0x02810UL
#define E1000_RDT_OFFSET 0x02818UL

#define E1000E_RX_BUF_SIZE 2048U

typedef union {
	struct {
		odpdrv_u64le_t buffer_addr;
		odpdrv_u64le_t reserved;
	} read;
	struct {
		struct {
			odpdrv_u32le_t mrq;			/* Multiple Rx Queues */
			union {
				odpdrv_u32le_t rss;		/* RSS Hash */
				struct {
					odpdrv_u16le_t ip_id;	/* IP id */
					odpdrv_u16le_t csum;	/* Packet Checksum */
				} csum_ip;
			} hi_dword;
		} lower;
		struct {
#define E1000E_RX_DESC_STAT_DONE	0x00000001UL
#define E1000E_RX_DESC_STAT_ERR_MASK	0xff000000UL
			odpdrv_u32le_t status_error;		/* ext status/error */
			odpdrv_u16le_t length;
			odpdrv_u16le_t vlan;			/* VLAN tag */
		} upper;
	} wb;							/* writeback */
} e1000e_rx_desc_t;

/** Packet socket using mediated e1000e device */
typedef struct {
	/* TODO: cache align everything when we have profiling information */
	odp_pool_t pool;		/**< pool to alloc packets from */

	/* volatile void *mmio; */
	void *mmio;			/**< BAR0 mmap */

	/* RX ring hot data */
	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_ticketlock_t rx_lock;	/**< RX ring lock */
	e1000e_rx_desc_t *rx_ring;	/**< RX ring mmap */
	struct iomem rx_data;		/**< RX packet payload mmap */
	uint16_t rx_next;		/**< next entry in RX ring to use */
	// rx_tail, rx_head ? (mmio + offset)

	/* TX ring hot data */
	odp_bool_t lockless_tx;		/**< no locking for TX */
	odp_ticketlock_t tx_lock;	/**< TX ring lock */
	e1000e_tx_desc_t *tx_ring;	/**< TX ring mmap */
	struct iomem tx_data;		/**< TX packet payload mmap */
	uint16_t tx_next;		/**< next entry in TX ring to use */
	// tx_tail, tx_head ? (mmio + offset)

	odp_pktio_capability_t capa;	/**< interface capabilities */

	int device;			/**< VFIO device */
	int group;			/**< VFIO group */

	size_t mmio_len;		/**< MMIO mmap'ed region length */
	size_t rx_ring_len;		/**< Rx ring mmap'ed region length */
	size_t tx_ring_len;		/**< Tx ring mmap'ed region length */
} pktio_ops_e1000e_data_t;

static pktio_ops_module_t e1000e_pktio_ops;

static void e1000e_rx_refill(pktio_ops_e1000e_data_t *pkt_e1000e,
			     uint16_t from, uint16_t num);

static int e1000e_open(odp_pktio_t id ODP_UNUSED,
		       pktio_entry_t * pktio_entry,
		       const char *netdev, odp_pool_t pool)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	struct vfio_iommu_type1_info iommu_info = { .argsz = sizeof(iommu_info) };
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	int container = -1, group = -1, device = -1;
	int ret;
	void *iobase, *iocur;
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);
	char group_uuid[64]; /* 37 should be enough */
	int group_id;

	printf("e1000e: probing %s\n", netdev);

	/* Init pktio entry */
	memset(pkt_e1000e, 0, sizeof(*pkt_e1000e));
	memset(group_uuid, 0, sizeof(group_uuid));

	if (pool == ODP_POOL_INVALID)
		return -EINVAL;

	pkt_e1000e->pool = pool;

	group_id =
	    mdev_sysfs_discover(netdev, e1000e_pktio_ops.base.name, group_uuid,
				sizeof(group_uuid));
	if (group_id < 0)
		return -EINVAL;

	pkt_e1000e->capa.max_input_queues = 1;
	pkt_e1000e->capa.max_output_queues = 1;

	odp_ticketlock_init(&pkt_e1000e->rx_lock);
	odp_ticketlock_init(&pkt_e1000e->tx_lock);

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
	pkt_e1000e->group = group;

	device = vfio_init_dev(group, container, &group_status, &iommu_info,
			       &device_info, group_uuid);
	if (device < 0)
		goto out;
	pkt_e1000e->device = device;

	/* Init device and mmaps */
	pkt_e1000e->mmio = vfio_mmap_region(device, 0, &pkt_e1000e->mmio_len);
	if (!pkt_e1000e->mmio) {
		printf("Cannot map MMIO\n");
		goto out;
	}

	pkt_e1000e->rx_ring = vfio_mmap_region(device, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_RX_REGION_INDEX,
					      &pkt_e1000e->rx_ring_len);
	if (!pkt_e1000e->rx_ring) {
		printf("Cannot map RxRing\n");
		goto out;
	}
	pkt_e1000e->tx_ring = vfio_mmap_region(device, VFIO_PCI_NUM_REGIONS +
					      VFIO_NET_MDEV_TX_REGION_INDEX,
					      &pkt_e1000e->tx_ring_len);
	if (!pkt_e1000e->tx_ring) {
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
	pkt_e1000e->rx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(device, &iocur, &pkt_e1000e->rx_data);
	if (ret)
		goto out;

	pkt_e1000e->tx_data.size = 2 * 1024 * 1024;
	ret = iomem_alloc_dma(device, &iocur, &pkt_e1000e->tx_data);
	if (ret)
		goto out;

	e1000e_rx_refill(pkt_e1000e, 0, E1000E_RX_RING_SIZE_DEFAULT - 1);

	printf("%s: starting initial wait\n", __func__);
	usleep(20 * 1000 * 1000);
	printf("%s: initial wait is complete\n", __func__);

	return 0;
out:
	if (group > 0)
		close(group);
	if (pkt_e1000e->tx_data.vaddr)
		iomem_free_dma(device, &pkt_e1000e->tx_data);
	if (pkt_e1000e->rx_data.vaddr)
		iomem_free_dma(device, &pkt_e1000e->rx_data);
	if (pkt_e1000e->tx_ring)
		munmap(pkt_e1000e->tx_ring, pkt_e1000e->tx_ring_len);
	if (pkt_e1000e->rx_ring)
		munmap(pkt_e1000e->rx_ring, pkt_e1000e->rx_ring_len);
	if (pkt_e1000e->mmio)
		munmap(pkt_e1000e->mmio, pkt_e1000e->mmio_len);
	if (container > 0)
		close(container);
	if (iobase)
		iomem_free(iobase);

	return -1;
}


static int e1000e_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);

	if (pkt_e1000e->group > 0)
		close(pkt_e1000e->group);
	if (pkt_e1000e->tx_data.vaddr)
		iomem_free_dma(pkt_e1000e->device, &pkt_e1000e->tx_data);
	if (pkt_e1000e->rx_data.vaddr)
		iomem_free_dma(pkt_e1000e->device, &pkt_e1000e->rx_data);
	if (pkt_e1000e->tx_ring)
		munmap(pkt_e1000e->tx_ring, pkt_e1000e->tx_ring_len);
	if (pkt_e1000e->rx_ring)
		munmap(pkt_e1000e->rx_ring, pkt_e1000e->rx_ring_len);
	if (pkt_e1000e->mmio)
		munmap(pkt_e1000e->mmio, pkt_e1000e->mmio_len);

	return 0;
}

static void e1000e_rx_refill(pktio_ops_e1000e_data_t *pkt_e1000e,
			     uint16_t from, uint16_t num)
{
	uint16_t i = from;

	/* Need 1 desc gap to keep tail from touching head */
	// TODO: ODP_ASSERT(num < E1000E_RX_RING_SIZE_DEFAULT);

	while (num) {
		e1000e_rx_desc_t *rx_desc = &pkt_e1000e->rx_ring[i];
		dma_addr_t dma_addr =
		    pkt_e1000e->rx_data.iova + i * E1000E_RX_BUF_SIZE;

		rx_desc->read.buffer_addr = odpdrv_cpu_to_le_64(dma_addr);
		// rx_desc->read.reserved
		// rx_desc->wb

		i++;
		if (i == E1000E_RX_RING_SIZE_DEFAULT)
			i = 0;
		num--;
	}

	dma_wmb();

	io_write32(odpdrv_cpu_to_le_32(i),
		   (char *)pkt_e1000e->mmio + E1000_RDT_OFFSET);
}

static int e1000e_recv(pktio_entry_t * pktio_entry, int index ODP_UNUSED,
		       odp_packet_t pkt_table[], int num)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);
	uint16_t refill_from;
	uint16_t budget = 0;
	int rx_pkts = 0;

	/* Keep track of the start point to refill RX ring */
	refill_from = pkt_e1000e->rx_next;

	/*
	 * Determine how many packets are available in RX ring:
	 *     (Write_index - Read_index) modulo RX_ring_size
	 */
	budget += io_read32((char *)pkt_e1000e->mmio + E1000_RDH_OFFSET);
	budget -= pkt_e1000e->rx_next;
	budget &= E1000E_RX_RING_SIZE_DEFAULT - 1;

	if (budget > num)
		budget = num;

	budget = odp_packet_alloc_multi(pkt_e1000e->pool, E1000E_RX_BUF_SIZE,
					pkt_table, budget);

	while (rx_pkts < budget) {
		volatile e1000e_rx_desc_t *rx_desc =
		    &pkt_e1000e->rx_ring[pkt_e1000e->rx_next];
		odp_packet_hdr_t *pkt_hdr;
		odp_packet_t pkt;
		uint16_t pkt_len;
		uint32_t status;

		/* TODO: let the HW drop all erroneous packets */
		status = odpdrv_le_to_cpu_32(rx_desc->wb.upper.status_error);
		if (odp_unlikely(status & E1000E_RX_DESC_STAT_ERR_MASK)) {
			pkt_e1000e->rx_next++;
			if (pkt_e1000e->rx_next >= E1000E_RX_RING_SIZE_DEFAULT)
				pkt_e1000e->rx_next = 0;
			odp_packet_free_multi(&pkt_table[rx_pkts],
					      budget - rx_pkts);
			break;
		}

		pkt_len = odpdrv_le_to_cpu_16(rx_desc->wb.upper.length);
		pkt = pkt_table[rx_pkts];
		pkt_hdr = odp_packet_hdr(pkt);

		pull_tail(pkt_hdr, E1000E_RX_BUF_SIZE - pkt_len);

		/* FIXME: check return value  */
		odp_packet_copy_from_mem(pkt, 0, pkt_len,
					 pkt_e1000e->rx_data.vaddr +
					 pkt_e1000e->rx_next *
					 E1000E_RX_BUF_SIZE);

		pkt_hdr->input = pktio_entry->s.handle;

		pkt_e1000e->rx_next++;
		if (pkt_e1000e->rx_next >= E1000E_RX_RING_SIZE_DEFAULT)
			pkt_e1000e->rx_next = 0;

		rx_pkts++;
	}

	e1000e_rx_refill(pkt_e1000e, refill_from, rx_pkts);

	return rx_pkts;
}

static int e1000e_send(pktio_entry_t * pktio_entry, int index ODP_UNUSED,
		       const odp_packet_t pkt_table[], int num)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);
	int tx_pkts = 0;
	uint16_t budget;

	if (!pkt_e1000e->lockless_tx)
		odp_ticketlock_lock(&pkt_e1000e->tx_lock);

	/* Determine how many packets will fit in TX ring */
	budget = E1000E_TX_RING_SIZE_DEFAULT - 1;
	budget -= pkt_e1000e->tx_next;
	budget +=
	    odp_le_to_cpu_32(io_read32
			     ((char *)pkt_e1000e->mmio + E1000_TDH_OFFSET));
	budget &= E1000E_TX_RING_SIZE_DEFAULT - 1;

	if (budget > num)
		budget = num;

	while (budget) {
		volatile e1000e_tx_desc_t *tx_desc =
		    &pkt_e1000e->tx_ring[pkt_e1000e->tx_next];
		uint16_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);
		uint32_t offset = pkt_e1000e->tx_next * E1000E_TX_BUF_SIZE;
		uint32_t txd_cmd = E1000_TXD_CMD_IFCS | E1000_TXD_CMD_EOP;

		/* Skip oversized packets silently */
		if (odp_unlikely(pkt_len > E1000E_TX_BUF_SIZE)) {
			tx_pkts++;
			continue;
		}

		odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
				       pkt_e1000e->tx_data.vaddr + offset);

		tx_desc->buffer_addr =
		    odp_cpu_to_le_64(pkt_e1000e->tx_data.iova + offset);
		tx_desc->lower.data = odp_cpu_to_le_32(txd_cmd | pkt_len);
		tx_desc->upper.data = odp_cpu_to_le_32(0);

		pkt_e1000e->tx_next++;
		if (odp_unlikely(pkt_e1000e->tx_next >= E1000E_TX_RING_SIZE_DEFAULT))
			pkt_e1000e->tx_next = 0;

		tx_pkts++;
		budget--;
	}

	dma_wmb();

	io_write32(odp_cpu_to_le_32(pkt_e1000e->tx_next),
		   (char *)pkt_e1000e->mmio + E1000_TDT_OFFSET);

	if (!pkt_e1000e->lockless_tx)
		odp_ticketlock_unlock(&pkt_e1000e->tx_lock);

	if (odp_unlikely(tx_pkts == 0)) {
		if (odp_errno() != 0)
			return -1;
	} else {
		odp_packet_free_multi(pkt_table, tx_pkts);
	}

	return tx_pkts;
}

static pktio_ops_module_t e1000e_pktio_ops = {
	.base = {
		 .name = "e1000e",
	},

	.open = e1000e_open,
	.close = e1000e_close,

	.recv = e1000e_recv,
	.send = e1000e_send,
};

/** e1000e module entry point */
static void ODPDRV_CONSTRUCTOR e1000e_module_init(void)
{
	odp_module_constructor(&e1000e_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &e1000e_pktio_ops);
}
