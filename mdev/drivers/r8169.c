#include <odp_posix_extensions.h>
#include <stdio.h>
#include <endian.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>

#include <odp/drv/byteorder.h>
#include <odp/api/hints.h>

#include <drivers/r8169.h>
#include <drivers/driver_ops.h>
#include <mm_api.h>
#include <reg_api.h>
#include <vfio_api.h>

typedef unsigned long dma_addr_t;

/* test udp packet */
char pkt_udp[] = {
	0x02, 0x50, 0x43, 0xff, 0xff, 0x01, /* mac dst */
	0x00, 0x60, 0xdd, 0x45, 0xe5, 0x67, /* mac src */
	0x08, 0x00, 0x45, 0x00, 0x00, 0x32,
	0x38, 0xb8, 0x40, 0x00, 0x40, 0x11,
	0x1e, 0xae, 0xc0, 0xa8, 0x31, 0x03, /* ip src: 192.168.49.3 and dst 192.168.49.1 */
	0xc0, 0xa8, 0x31, 0x01, 0xed, 0x19,
	0x00, 0x35, 0x00, 0x1e, 0x8b, 0xf4,
	0xc4, 0x2e, 0x01, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
	0x00, 0x01, 0x00, 0x01
};

static inline void rtl8169_mark_to_asic(struct r8169_rxdesc *desc, __u32 rx_buf_sz)
{
	__u32 eor = odpdrv_le_to_cpu_32(desc->opts1) & RingEnd;

	/* Force memory writes to complete before releasing descriptor */
	dma_wmb();

	desc->opts1 = odpdrv_cpu_to_le_32(DescOwn | eor | rx_buf_sz);
}

static inline void rtl8169_map_to_asic_rx(struct r8169_rxdesc *desc, dma_addr_t mapping,
					  __u32 rx_buf_sz)
{
	desc->addr = odpdrv_cpu_to_le_64(mapping);
	rtl8169_mark_to_asic(desc, rx_buf_sz);
}

static inline void rtl8169_mark_as_last_descriptor(struct r8169_rxdesc *desc)
{
	desc->opts1 |= odpdrv_cpu_to_le_32(RingEnd);
}

static int r8169_rx_fill(void *rx_data, struct iomem data, char *rx_buff[],
			 volatile void *ioaddr)
{
	unsigned int i;
	struct r8169_rxdesc *r8169_rxring = (struct r8169_rxdesc *) rx_data;

	if (!ioaddr)
		return -1;

	for (i = 0; i < NUM_RX_DESC; i++) {
		rtl8169_map_to_asic_rx(&r8169_rxring[i], data.iova + i * 2048, 2048);
		rx_buff[i] = (char *)(data.vaddr + i * 2048);
	}
	rtl8169_mark_as_last_descriptor(&r8169_rxring[NUM_RX_DESC - 1]);

	return 0;
}

static void r8169_recv(void *rxring, char *rx_buff[] ODP_UNUSED, volatile void *ioaddr)
{
	unsigned int i = 0;
	struct r8169_rxdesc *r8169_rxring = (struct r8169_rxdesc *)rxring;

	if(!ioaddr)
		return;

	while (1) {
		if (i >= NUM_RX_DESC)
			i = 0;
		for (; i < NUM_RX_DESC; i++) {
			__u32 status;

			status = odpdrv_le_to_cpu_32(r8169_rxring[i].opts1) & ~0; /// either  ~(RxBOVF | RxFOVF) or ~0;

			if (status & DescOwn) {
				usleep(100*1000);
				break;
			}
			/* This barrier is needed to keep us from reading
			* any other fields out of the Rx descriptor until
			* we know the status of DescOwn
			*/
			dma_rmb();

			if (unlikely(status & RxRES)) {
				printf("Rx ERROR. status = %08x\n",status);
				if ((status & (RxRUNT | RxCRC)) &&
					!(status & (RxRWT | RxFOVF))
					/* && 	(dev->features & NETIF_F_RXALL) */
					)
					goto process_pkt;
			} else {
				int pkt_size;
process_pkt:
				if (1) // likely(!(dev->features & NETIF_F_RXFCS)))
					pkt_size = (status & 0x00003fff) - 4;
				else
					pkt_size = status & 0x00003fff;

				printf("desc[%03d]: size= %5d ", i, pkt_size);
				printf("\n");
			}
			/* release_descriptor: */
			r8169_rxring[i].opts2 = 0;
			rtl8169_mark_to_asic(&r8169_rxring[i], 2048);
		}
	}
}

static inline void rtl8169_map_to_asic_tx(struct r8169_txdesc *desc, dma_addr_t mapping)

{
	desc->addr = odpdrv_cpu_to_le_64(mapping);
}

static void r8169_xmit(void *txring, struct iomem data, volatile void *ioaddr)
{
	const int idx = 0;
	__u32 opts[2];
	__u32 status, len;
	int entry = 0;
	struct r8169_txdesc *r8169_txring = (struct r8169_txdesc *)txring;
	char *tx_buff = (char *)(data.vaddr + idx * 2048);

	/* XXX FIXME need proper packet size and sizeof(src) *NOT* dst */
	memcpy(tx_buff, pkt_udp, sizeof(pkt_udp));
	rtl8169_map_to_asic_tx(&r8169_txring[idx], data.iova + idx * 2048);
	/* FIXME no fragmentation support */
	opts[0] = DescOwn;
	opts[0] |= FirstFrag | LastFrag;
	/* FIXME No vlan support */
	opts[1] = odpdrv_cpu_to_le_32(0x00);
	/* FIXME get actual packet size */
	len = sizeof(pkt_udp);

	status = opts[0] | len | (RingEnd * !((entry + 1) % NUM_TX_DESC));
	r8169_txring->opts1 = odpdrv_cpu_to_le_32(status);
	r8169_txring->opts2 = odpdrv_cpu_to_le_32(opts[1]);
	io_write8(NPQ, (volatile char *)ioaddr + TxPoll);

	return;
}

static void *r8169_map_mmio(int device, size_t *len)
{
	void *mmio;

	mmio = vfio_mmap_region(device, 2, len);

	return mmio;
}

/* FIXME make this staic once we have loadbale module support */
const struct driver_ops r8169_ops = {
	/* endianess for vendor/id? */
	.vendor = 0x10ec,
	.device = 0x8168,
	.vfio_quirks = NULL,
	.rx_fill = r8169_rx_fill,
	.recv = r8169_recv,
	.xmit = r8169_xmit,
	.map_mmio = r8169_map_mmio,
};
