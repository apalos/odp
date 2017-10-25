#ifndef _VFIO_API_H
#define _VFIO_API_H
#include <linux/vfio.h>
int dma_map_type1(int fd, unsigned long sz, void **vaddr, uint64_t iova);
int dma_unmap_type1(int fd, unsigned long sz, void *vaddr, uint64_t iova);
int get_group(int grp_id);
int get_container(void);
int vfio_init_dev(int grp, int container, struct vfio_group_status *grp_status,
		  struct vfio_iommu_type1_info *iommu_info,
		  struct vfio_device_info *dev_info, char *grp_uuid);
int vfio_get_region(int device, struct vfio_region_info *reg_info, __u32 region);
void *vfio_mmap_region(int device, __u32 region, size_t *len);
int iomem_alloc_dma(int device, unsigned int size, void **iomem_curent,
		    struct iomem *iomem);
#endif
