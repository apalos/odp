#ifndef _VFIO_API_H
#define _VFIO_API_H

#include <linux/vfio.h>
#include <net/if.h>

#include <mm_api.h>

typedef struct {
	__u16 type;
	__u16 subtype;
} mdev_region_class_t;

typedef struct {
	char if_name[IF_NAMESIZE];	/**< Interface name */

	int container;
	int group;
	int device;

	int group_id;
	char group_uuid[64];

	uint8_t *iobase;
	uint8_t *iocur;

	struct {
		uint8_t *addr;
		size_t size;
	} mappings[256];
	uint16_t mappings_count;
} mdev_device_t;

typedef int (*mdev_region_info_cb_t)(mdev_device_t *,
				     struct vfio_region_info *);

int mdev_device_create(mdev_device_t * mdev, const char *mod_name,
		       const char *if_name, mdev_region_info_cb_t cb);
void mdev_device_destroy(mdev_device_t *mdev);

void *mdev_region_mmap(mdev_device_t *mdev, uint64_t offset, uint64_t size);

int iomem_alloc_dma(mdev_device_t *mdev, struct iomem *iomem);
int iomem_free_dma(mdev_device_t *mdev, struct iomem *iomem);

int mdev_attr_get(mdev_device_t *mdev, const char *attr, char *buf);
int mdev_attr_u64_get(mdev_device_t *mdev, const char *attr, uint64_t *val);
int mdev_attr_u32_get(mdev_device_t *mdev, const char *attr, uint32_t *val);
int mdev_attr_u16_get(mdev_device_t *mdev, const char *attr, uint16_t *val);
int mdev_attr_u8_get(mdev_device_t *mdev, const char *attr, uint8_t *val);

int vfio_get_region_cap_type(struct vfio_region_info *region_info,
			     mdev_region_class_t *type_info);
int vfio_get_region_sparse_mmaps(struct vfio_region_info *region_info,
				 struct vfio_region_info_cap_sparse_mmap **sparse);


#endif
