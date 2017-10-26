#include <odp_posix_extensions.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>

#include <odp/drv/byteorder.h>
#include <odp/api/hints.h>

#include <drivers/driver_ops.h>
#include <mm_api.h>
#include <vfio_api.h>
#include <reg_api.h>

/* Common code. TODO: relocate */
#if 1
#define dma_wmb()
#define dma_rmb()
#define unlikely(x) (x)
#endif

/* TX ring definitions */
#define E1000E_TX_RING_SIZE_DEFAULT 256
#define E1000E_TX_RING_SIZE_MIN 64
#define E1000E_TX_RING_SIZE_MAX 4096

#define E1000_TDH_OFFSET 0x03810UL
#define E1000_TDT_OFFSET 0x03818UL

typedef struct e1000e_tx_desc {
	odpdrv_u64le_t buffer_addr;		/* Address of the descriptor's data buffer */
	union {
#define E1000_TXD_CMD_EOP	0x01000000	/* End of Packet */
#define E1000_TXD_CMD_IFCS	0x02000000	/* Insert FCS (Ethernet CRC) */
#define E1000_TXD_CMD_RS	0x08000000	/* Report Status */
#define E1000_TXD_CMD_IDE	0x80000000	/* Enable Tidv register */

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
} e1000_tx_desc_t;

/* RX ring definitions */
#define E1000E_RX_RING_SIZE_DEFAULT 256
#define E1000E_RX_RING_SIZE_MIN 64
#define E1000E_RX_RING_SIZE_MAX 4096

#define E1000_RDH_OFFSET 0x02810UL
#define E1000_RDT_OFFSET 0x02818UL

#define E1000E_RX_BUF_SIZE 2048

typedef union e1000e_rx_desc {
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

/* Common code. TODO: relocate */
typedef unsigned long dma_addr_t;

static void e1000e_rx_desc_push(e1000e_rx_desc_t *rx_ring, int idx, dma_addr_t dma_addr,
				volatile void *ioaddr)
{
	rx_ring[idx].read.buffer_addr = odpdrv_cpu_to_le_64(dma_addr);
	dma_wmb();

	io_write32(odpdrv_cpu_to_le_32(idx), (volatile char *)ioaddr + E1000_RDT_OFFSET);
}

static int e1000e_rx_fill(void *rxring, struct iomem data,
			   char *rx_buff[], volatile void *ioaddr)
{
	e1000e_rx_desc_t *rx_ring = (e1000e_rx_desc_t *)rxring;
	int i;

	/* TODO: support variable rx_ring size, configuration via ethtool */
	for (i = 0; i < E1000E_RX_RING_SIZE_DEFAULT; i++) {
		rx_buff[i] = (char *)(data.vaddr + i * E1000E_RX_BUF_SIZE);
		e1000e_rx_desc_push(rx_ring, i, data.iova + i * E1000E_RX_BUF_SIZE, ioaddr);
	}

	return 0;
}

static void e1000e_recv(void *rxring, char *rx_buff[] ODP_UNUSED, volatile void *ioaddr)
{
	e1000e_rx_desc_t *rx_ring = (e1000e_rx_desc_t *)rxring;
	int i = 0;

	if (!ioaddr)
		return;

	while (1) {
		if (i >= E1000E_RX_RING_SIZE_DEFAULT)
			i = 0;
		for (; i < E1000E_RX_RING_SIZE_DEFAULT; i++) {
			e1000e_rx_desc_t *rx_desc = rx_ring + i;
			uint32_t status = odpdrv_le_to_cpu_32(rx_desc->wb.upper.status_error);

			if (!(status & E1000E_RX_DESC_STAT_DONE)) {
				usleep(100*1000);
				break;
			}

			/* This barrier is needed to keep us from reading
			* any other fields out of the Rx descriptor until
			* we know the status of DescOwn
			*/
			dma_rmb();

			if (unlikely(status & E1000E_RX_DESC_STAT_ERR_MASK)) {
				printf("Rx ERROR. status = %08x\n", status);
			} else {
				int pkt_size = odpdrv_le_to_cpu_16(rx_desc->wb.upper.length);

				printf("desc[%03d]: size= %5d ", i, pkt_size);
				//print_packet((unsigned char *)rx_buff[i]);
				printf("\n");
			}
			/* release_descriptor: */
			// e1000e_rx_desc_push(rx_ring, i, data.iova + i * E1000E_RX_BUF_SIZE);
		}
	}
}

static void *e1000e_map_mmio(int device, size_t *len)
{
	return vfio_mmap_region(device, 0, len);
}

const struct driver_ops e1000e_ops = {
	.vendor = 0x8086,
	.device = 0xdead,
	.vfio_quirks = NULL,
	.rx_fill = e1000e_rx_fill,
	.recv = e1000e_recv,
	.map_mmio = e1000e_map_mmio,
};
