#ifndef _VFIO_API_H
#define _VFIO_API_H
#include <linux/vfio.h>

typedef struct {
	int container;
	int group;
	int device;

	int group_id;
	char group_uuid[64];

	uint8_t *iobase;
	uint8_t *iocur;
} mdev_device_t;

int mdev_device_create(mdev_device_t *mdev, const char *mod_name, const char *if_name);
void mdev_device_destroy(mdev_device_t *mdev);

void *vfio_mmap_region(mdev_device_t *mdev, __u32 region, size_t *len);
int iomem_alloc_dma(mdev_device_t *mdev, struct iomem *iomem);
int iomem_free_dma(mdev_device_t *mdev, struct iomem *iomem);

#endif
