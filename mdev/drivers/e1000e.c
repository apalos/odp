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

#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>
#include <ethtool_api.h>
#include <sysfs_parse.h>
#include <eth_stats.h>
#include <common.h>

#include <uapi/net_mdev.h>

#define MODULE_NAME "e1000e"

#define E1000E_TX_BUF_SIZE 2048U
#define E1000E_RX_BUF_SIZE 2048U

/* TX queue definitions */
#define E1000_TDH_OFFSET 0x03810UL
#define E1000_TDT_OFFSET 0x03818UL

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

/* RX queue definitions */
#define E1000_RDH_OFFSET 0x02810UL
#define E1000_RDT_OFFSET 0x02818UL

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
	odp_pool_t pool;		/**< pool to alloc packets from */

	/* volatile void *mmio; */
	uint8_t *mmio;			/**< BAR0 mmap */

	/* RX queue hot data */
	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_ticketlock_t rx_lock;	/**< RX queue lock */
	e1000e_rx_desc_t *rx_descs;	/**< RX queue mmap */
	struct iomem rx_data;		/**< RX packet payload mmap */
	uint16_t rx_next;		/**< next entry in RX queue to use */
	uint16_t rx_queue_len;		/**< Number of RX desc entries */

	/* TX queue hot data */
	odp_bool_t lockless_tx;		/**< no locking for TX */
	odp_ticketlock_t tx_lock;	/**< TX queue lock */
	e1000e_tx_desc_t *tx_descs;	/**< TX queue mmap */
	struct iomem tx_data;		/**< TX packet payload mmap */
	uint16_t tx_next;		/**< next entry in TX queue to use */
	uint16_t tx_queue_len;		/**< Number of TX desc entries */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_e1000e_data_t;

static pktio_ops_module_t e1000e_pktio_ops;

static void e1000e_rx_refill(pktio_ops_e1000e_data_t *pkt_e1000e,
			     uint16_t from, uint16_t num);
static void e1000e_wait_link_up(pktio_entry_t *pktio_entry);
static int e1000e_close(pktio_entry_t *pktio_entry);

static int e1000e_mmio_register(pktio_ops_e1000e_data_t *pkt_e1000e,
				uint64_t offset, uint64_t size)
{
	ODP_ASSERT(pkt_e1000e->mmio == NULL);

	pkt_e1000e->mmio = mdev_region_mmap(&pkt_e1000e->mdev, offset, size);
	if (pkt_e1000e->mmio == MAP_FAILED) {
		ODP_ERR("Cannot mmap MMIO\n");
		return -1;
	}

	ODP_DBG("Register MMIO region: 0x%llx@%016llx\n", size, offset);

	return 0;
}

static int e1000e_rx_queue_register(pktio_ops_e1000e_data_t *pkt_e1000e,
				    uint64_t offset, uint64_t size)
{
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(pkt_e1000e->capa.max_input_queues == 0);

	ret = mdev_ringparam_get(&pkt_e1000e->mdev, &ering);
	if (ret) {
		ODP_ERR("Cannot get ethtool parameters\n");
		return -1;
	}
	pkt_e1000e->rx_queue_len = ering.rx_pending;

	pkt_e1000e->rx_descs = mdev_region_mmap(&pkt_e1000e->mdev, offset, size);
	if (pkt_e1000e->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
		return -1;
	}

	pkt_e1000e->rx_data.size = pkt_e1000e->rx_queue_len * E1000E_RX_BUF_SIZE;
	ret = iomem_alloc_dma(&pkt_e1000e->mdev, &pkt_e1000e->rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}

	e1000e_rx_refill(pkt_e1000e, 0, pkt_e1000e->rx_queue_len - 1);

	pkt_e1000e->capa.max_input_queues++;

	ODP_DBG("Register RX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX descriptors: %u\n", pkt_e1000e->rx_queue_len);

	return 0;
}

static int e1000e_tx_queue_register(pktio_ops_e1000e_data_t *pkt_e1000e,
				    uint64_t offset, uint64_t size)
{
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(pkt_e1000e->capa.max_output_queues == 0);

	ret = mdev_ringparam_get(&pkt_e1000e->mdev, &ering);
	if (ret) {
		ODP_ERR("Cannot get ethtool parameters\n");
		return -1;
	}
	pkt_e1000e->tx_queue_len = ering.tx_pending;

	pkt_e1000e->tx_descs = mdev_region_mmap(&pkt_e1000e->mdev, offset, size);
	if (pkt_e1000e->tx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap TX queue\n");
		return -1;
	}

	pkt_e1000e->tx_data.size = pkt_e1000e->tx_queue_len * E1000E_TX_BUF_SIZE;
	ret = iomem_alloc_dma(&pkt_e1000e->mdev, &pkt_e1000e->tx_data);
	if (ret) {
		ODP_ERR("Cannot allocate TX queue DMA area\n");
		return -1;
	}

	pkt_e1000e->capa.max_output_queues++;

	ODP_DBG("Register TX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    TX descriptors: %u\n", pkt_e1000e->tx_queue_len);

	return 0;
}

static int e1000e_region_info_cb(mdev_device_t *mdev,
				 struct vfio_region_info *region_info)
{
	pktio_ops_e1000e_data_t *pkt_e1000e =
	    odp_container_of(mdev, pktio_ops_e1000e_data_t, mdev);
	int ret;
	mdev_region_class_t class_info;

	ret = vfio_get_region_cap_type(region_info, &class_info);
	if (ret < 0)
		return ret;

	/*
	 * TODO: parse region_info capabilities instead of hardcoded region
	 * index and call relevant hook
	 */
	switch (class_info.type) {
	case VFIO_NET_MMIO:
		ret =
		    e1000e_mmio_register(pkt_e1000e, region_info->offset,
					 region_info->size);
		break;

	case VFIO_NET_DESCRIPTORS:
		if (class_info.subtype == VFIO_NET_MDEV_RX)
			ret =
				e1000e_rx_queue_register(pkt_e1000e, region_info->offset,
							 region_info->size);
		else if (class_info.subtype == VFIO_NET_MDEV_TX)
			ret =
				e1000e_tx_queue_register(pkt_e1000e, region_info->offset,
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

static int e1000e_open(odp_pktio_t id ODP_UNUSED,
		       pktio_entry_t *pktio_entry,
		       const char *resource, odp_pool_t pool)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);
	int ret;

	ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	memset(pkt_e1000e, 0, sizeof(*pkt_e1000e));

	ODP_DBG("%s: probing resource %s\n", MODULE_NAME, resource);

	ret =
	    mdev_device_create(&pkt_e1000e->mdev, MODULE_NAME,
			       resource + strlen(NET_MDEV_PREFIX),
			       e1000e_region_info_cb);
	if (ret)
		goto out;

	pkt_e1000e->pool = pool;

	odp_ticketlock_init(&pkt_e1000e->rx_lock);
	odp_ticketlock_init(&pkt_e1000e->tx_lock);

	e1000e_wait_link_up(pktio_entry);

	ODP_DBG("%s: open %s is successful\n", MODULE_NAME,
		pkt_e1000e->mdev.if_name);

	return 0;

out:
	e1000e_close(pktio_entry);
	return -1;
}

static int e1000e_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);

	ODP_DBG("%s: close %s\n", MODULE_NAME, pkt_e1000e->mdev.if_name);

	mdev_device_destroy(&pkt_e1000e->mdev);

	if (pkt_e1000e->tx_data.vaddr)
		iomem_free_dma(&pkt_e1000e->mdev, &pkt_e1000e->tx_data);
	if (pkt_e1000e->rx_data.vaddr)
		iomem_free_dma(&pkt_e1000e->mdev, &pkt_e1000e->rx_data);

	return 0;
}

static void e1000e_rx_refill(pktio_ops_e1000e_data_t *pkt_e1000e,
			     uint16_t from, uint16_t num)
{
	uint16_t i = from;

	/* Need 1 desc gap to keep tail from touching head */
	ODP_ASSERT(num < pkt_e1000e->rx_queue_len);

	while (num) {
		e1000e_rx_desc_t *rxd = &pkt_e1000e->rx_descs[i];
		uint32_t offset = i * E1000E_RX_BUF_SIZE;

		rxd->read.buffer_addr =
		    odpdrv_cpu_to_le_64(pkt_e1000e->rx_data.iova + offset);
		// rxd->read.reserved
		// rxd->wb

		i++;
		if (i == pkt_e1000e->rx_queue_len)
			i = 0;
		num--;
	}

	dma_wmb();

	io_write32(odpdrv_cpu_to_le_32(i), pkt_e1000e->mmio + E1000_RDT_OFFSET);
}

static int e1000e_recv(pktio_entry_t * pktio_entry, int index ODP_UNUSED,
		       odp_packet_t pkt_table[], int num)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);
	uint16_t refill_from;
	uint16_t budget = 0;
	int rx_pkts = 0;

	/* Keep track of the start point to refill RX queue */
	refill_from = pkt_e1000e->rx_next;

	/*
	 * Determine how many packets are available in RX queue:
	 *     (Write_index - Read_index) modulo RX queue size
	 */
	budget += io_read32(pkt_e1000e->mmio + E1000_RDH_OFFSET);
	budget -= pkt_e1000e->rx_next;
	budget &= pkt_e1000e->rx_queue_len - 1;

	if (budget > num)
		budget = num;

	budget = odp_packet_alloc_multi(pkt_e1000e->pool, E1000E_RX_BUF_SIZE,
					pkt_table, budget);

	while (rx_pkts < budget) {
		volatile e1000e_rx_desc_t *rxd =
		    &pkt_e1000e->rx_descs[pkt_e1000e->rx_next];
		odp_packet_hdr_t *pkt_hdr;
		odp_packet_t pkt;
		uint16_t pkt_len;
		uint32_t status;

		/* TODO: let the HW drop all erroneous packets */
		status = odpdrv_le_to_cpu_32(rxd->wb.upper.status_error);
		if (odp_unlikely(status & E1000E_RX_DESC_STAT_ERR_MASK)) {
			pkt_e1000e->rx_next++;
			if (pkt_e1000e->rx_next >= pkt_e1000e->rx_queue_len)
				pkt_e1000e->rx_next = 0;
			odp_packet_free_multi(&pkt_table[rx_pkts],
					      budget - rx_pkts);
			break;
		}

		pkt_len = odpdrv_le_to_cpu_16(rxd->wb.upper.length);
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
		if (odp_unlikely(pkt_e1000e->rx_next >= pkt_e1000e->rx_queue_len))
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

	/* Determine how many packets will fit in TX queue */
	budget = pkt_e1000e->tx_queue_len - 1;
	budget -= pkt_e1000e->tx_next;
	budget +=
	    odpdrv_le_to_cpu_32(io_read32
			     (pkt_e1000e->mmio + E1000_TDH_OFFSET));
	budget &= pkt_e1000e->tx_queue_len - 1;

	if (budget > num)
		budget = num;

	while (tx_pkts < budget) {
		volatile e1000e_tx_desc_t *txd =
		    &pkt_e1000e->tx_descs[pkt_e1000e->tx_next];
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

		txd->buffer_addr =
		    odpdrv_cpu_to_le_64(pkt_e1000e->tx_data.iova + offset);
		txd->lower.data = odpdrv_cpu_to_le_32(txd_cmd | pkt_len);
		txd->upper.data = odpdrv_cpu_to_le_32(0);

		pkt_e1000e->tx_next++;
		if (odp_unlikely(pkt_e1000e->tx_next >= pkt_e1000e->tx_queue_len))
			pkt_e1000e->tx_next = 0;

		tx_pkts++;
	}

	dma_wmb();

	io_write32(odpdrv_cpu_to_le_32(pkt_e1000e->tx_next),
		   pkt_e1000e->mmio + E1000_TDT_OFFSET);

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

static int e1000e_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = odp_ops_data(pktio_entry, e1000e);

	return mdev_get_iff_link(pkt_e1000e->mdev.if_name);
}

/* TODO: move to common code */
static void e1000e_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!e1000e_link_status(pktio_entry)) {
		sleep(1);
	}
}

static pktio_ops_module_t e1000e_pktio_ops = {
	.base = {
		 .name = MODULE_NAME,
	},

	.open = e1000e_open,
	.close = e1000e_close,

	.recv = e1000e_recv,
	.send = e1000e_send,

	.link_status = e1000e_link_status,
};

/** e1000e module entry point */
static void ODPDRV_CONSTRUCTOR e1000e_module_init(void)
{
	odp_module_constructor(&e1000e_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &e1000e_pktio_ops);
}
