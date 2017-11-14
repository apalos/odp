#ifndef _VFIO_API_H
#define _VFIO_API_H

#include <linux/vfio.h>
#include <net/if.h>

#include <mm_api.h>

typedef struct {
	int container;
	int group;
	int device;

	int group_id;
	char group_uuid[64];

	uint8_t *iobase;
	uint8_t *iocur;

	char if_name[IF_NAMESIZE];	/**< Interface name */
} mdev_device_t;

typedef int (*mdev_region_info_cb_t)(mdev_device_t *,
				     struct vfio_region_info *);

int mdev_device_create(mdev_device_t * mdev, const char *mod_name,
		       const char *if_name, mdev_region_info_cb_t cb);
void mdev_device_destroy(mdev_device_t *mdev);

void *mdev_region_mmap(mdev_device_t *mdev, uint64_t offset, uint64_t size);

int iomem_alloc_dma(mdev_device_t *mdev, struct iomem *iomem);
int iomem_free_dma(mdev_device_t *mdev, struct iomem *iomem);

#endif
