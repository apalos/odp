#include <stdio.h>
#include <endian.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>

#include <drivers/driver_ops.h>
#include <mm_api.h>
#include <vfio_api.h>
#include <reg_api.h>

extern void *bar0;

/* Common code. TODO: relocate */
#if 1
/* TODO: move to API or use ODP headers */
typedef uint16_t odpdrv_u16le_t;
typedef uint16_t odpdrv_u16be_t;

typedef uint32_t odpdrv_u32le_t;
typedef uint32_t odpdrv_u32be_t;

typedef uint64_t odpdrv_u64le_t;
typedef uint64_t odpdrv_u64be_t;

#define odpdrv_cpu_to_le_64(value) (value)
#define odpdrv_cpu_to_le_32(value) (value)
#define odpdrv_cpu_to_le_16(value) (value)
#define odpdrv_le_to_cpu_64(value) (value)
#define odpdrv_le_to_cpu_32(value) (value)
#define odpdrv_le_to_cpu_16(value) (value)

#define COMPILER_BARRIER() asm volatile("" ::: "memory")
#define MEMORY_BARRIER() asm volatile ("mfence" ::: "memory")
#define STORE_BARRIER() asm volatile ("sfence" ::: "memory")
#define LOAD_BARRIER() asm volatile ("lfence" ::: "memory")
#define dma_wmb() STORE_BARRIER()
#define dma_rmb() LOAD_BARRIER()
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
#if 1
typedef unsigned long dma_addr_t;

static void print_packet(unsigned char *buffer)
{
	int i;
	printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x [%04x]:",
		buffer[6], buffer[7], buffer[8], buffer[9], buffer[10], buffer[11],
		buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5],
		be16toh(*((uint16_t*)(&buffer[12])))
	);

	for (i = 14; i < 32; i++) {
		printf("%02x", buffer[i]);
	}
}
#endif

static void e1000e_rx_desc_push(e1000e_rx_desc_t *rx_ring, int idx, dma_addr_t dma_addr,
				volatile void *ioaddr)
{
	rx_ring[idx].read.buffer_addr = odpdrv_cpu_to_le_64(dma_addr);
	dma_wmb();

	io_write32(odpdrv_cpu_to_le_32(idx), (volatile char *)ioaddr + E1000_RDT_OFFSET);
}

static int e1000e_rx_fill(int device, void *rxring, struct iomem data,
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

static void e1000e_recv(void *rxring, char *rx_buff[], volatile void *ioaddr)
{
	e1000e_rx_desc_t *rx_ring = (e1000e_rx_desc_t *)rxring;
	int i = 0;

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
				print_packet((unsigned char *)rx_buff[i]);
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

static void e1000e_xmit(void *txring, struct iomem data, volatile void *ioaddr)
{
	/* ARP request packet */
	static const unsigned char pkt_arp_req[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf4, 0x4d,
		0x30, 0x64, 0x43, 0xf7, 0x08, 0x06, 0x00, 0x01,
		0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xf4, 0x4d,
		0x30, 0x64, 0x43, 0xf7, 0xc0, 0xa8, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	int idx;
	uint32_t txd_cmd =
	    E1000_TXD_CMD_IFCS | E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS |
	    E1000_TXD_CMD_IDE;

	for (idx = 0; idx < 100; idx++) {
		volatile e1000_tx_desc_t *tx_desc =
		    (e1000_tx_desc_t *) txring + idx;
		volatile unsigned char *tx_buff =
		    (unsigned char *) (data.vaddr + idx * 2048);

		/* XXX FIXME need proper packet size and sizeof(src) *NOT* dst */
		memcpy((void *) tx_buff, pkt_arp_req, sizeof(pkt_arp_req));
		tx_desc->buffer_addr =
		    odpdrv_cpu_to_le_64(data.iova + idx * 2048);
		tx_desc->lower.data =
		    odpdrv_cpu_to_le_32(txd_cmd | sizeof(pkt_arp_req));
		tx_desc->upper.data = odpdrv_cpu_to_le_32(0);

		dma_wmb();

		printf("Triggering xmit of dummy packet\n");
		print_packet((void *) tx_buff);

#if 0
		printf("tx_desc->buffer_addr == 0x%016lx\n",
		       tx_desc->buffer_addr);
		printf("tx_desc->lower == 0x%08x\n", tx_desc->lower.data);
		printf("tx_desc->upper == 0x%08x\n", tx_desc->upper.data);
		printf("TDT == 0x%08x\n",
		       io_read32(ioaddr + E1000_TDT_OFFSET));
		printf("TDH == 0x%08x\n",
		       io_read32(ioaddr + E1000_TDH_OFFSET));

		usleep(100 * 1000);
#endif

		io_write32(odpdrv_cpu_to_le_32(idx + 1),
			   (volatile char *)ioaddr + E1000_TDT_OFFSET);

		usleep(100 * 1000);

#if 0
		printf("TDT == 0x%08x\n",
		       io_read32(ioaddr + E1000_TDT_OFFSET));
		printf("TDH == 0x%08x\n",
		       io_read32(ioaddr + E1000_TDH_OFFSET));
		printf("tx_desc->buffer_addr == 0x%016lx\n",
		       tx_desc->buffer_addr);
		printf("tx_desc->lower == 0x%08x\n", tx_desc->lower.data);
		printf("tx_desc->upper == 0x%08x\n", tx_desc->upper.data);
#endif
	}

	return;
}

const struct driver_ops e1000e_ops = {
	.vendor = 0x8086,
	.device = 0xdead,
	.vfio_quirks = NULL,
	.rx_fill = e1000e_rx_fill,
	.recv = e1000e_recv,
	.xmit = e1000e_xmit,
	.map_mmio = e1000e_map_mmio,
};

