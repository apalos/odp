#ifndef _DRIVER_OPS_H
#define _DRIVER_OPS_H
#include <mm_api.h>

struct driver_ops {
	__u16 vendor;
	__u16 device;
	/* VFIO/PCI quirks */
	int (*vfio_quirks)(void);
	/* prepare Rx descriptors */
	int (*rx_fill)(void *rxring, struct iomem data, char *rx_buf[],
		       volatile void *iomem);
	/* receive */
	void (*recv)(void *rxring, char *rxbuffers[], volatile void *iomem);
	/* xmit */
	void (*xmit)(void *txring, struct iomem data, volatile void *iomem);
	/* map MMIO */
	void *(*map_mmio)(int device, size_t *len);
};

struct _name_to_ops {
	const struct driver_ops *ops;
	const char *s;
};
#endif
