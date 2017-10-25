#ifndef _COMMON_H
#define _COMMON_H
#define OPT_DEV (1 << 0)
#define OPT_UUID (1 << 1)
#include <drivers/driver_ops.h>

#define TO_GB(x) (x * 1024ULL * 1024ULL * 1024ULL)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define container_of(ptr, type, member) \
({ \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member)); \
})


static inline int uio_quirks(const struct driver_ops *e)
{
	if (e && e->rx_fill)
		return e->vfio_quirks();

	return 0;
}

static inline int uio_rx_fill(const struct driver_ops *e, int device,
			      void *rxring, struct iomem data, char *rx_buf[],
			      volatile void *ioaddr)
{
	if (e && e->rx_fill)
		return e->rx_fill(device, rxring, data, rx_buf, ioaddr);

	return 0;
}

static inline void uio_recv(const struct driver_ops *e, void *rxring,
			    char *rxbuffers[], volatile void *iomem)
{
	if (e && e->recv)
		e->recv(rxring, rxbuffers, iomem);

	return;
}

static inline void uio_xmit(const struct driver_ops *e, void *txring,
			    struct iomem tx_data, volatile void *iomem)
{
	if (e && e->xmit)
		e->xmit(txring, tx_data, iomem);

	return;
}

static inline void *uio_map_mmio(const struct driver_ops *e, int device, size_t *len)
{

	if (e && e->map_mmio)
		return e->map_mmio(device, len);

	return NULL;
}
#endif
