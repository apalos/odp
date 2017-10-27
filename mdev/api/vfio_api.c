#include <odp_posix_extensions.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <linux/vfio.h>
#include <stddef.h>
#include <stdlib.h>

#include <odp_posix_extensions.h>

#include <common.h>
#include <uapi/net_mdev.h>
#include <vfio_api.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
static const char *vfio_fail_str[] = {
	[VFIO_CHECK_EXTENSION] = "Doesn't support the IOMMU driver we want",
	[VFIO_GROUP_GET_STATUS] = "Can't get status",
	[VFIO_GROUP_SET_CONTAINER] = "Failed to set container",
	[VFIO_SET_IOMMU] "Failed to set IOMMU",
	[VFIO_IOMMU_GET_INFO] = "Failed to get IOMMU info",
	[VFIO_GROUP_GET_DEVICE_FD] = "Failed to get device FD",
	[VFIO_DEVICE_GET_INFO] = "Failed to get device info",
	[VFIO_DEVICE_GET_REGION_INFO] = "Failed to get PCI region info",
};

static const struct cap_to_type_subtype {
	__u32 type;
	__u32 subtype;
} tmatch[] = {
	[VFIO_NET_MDEV_RX_REGION_INDEX] = { VFIO_NET_DESCRIPTORS, VFIO_NET_MDEV_RX },
	[VFIO_NET_MDEV_TX_REGION_INDEX] = { VFIO_NET_DESCRIPTORS, VFIO_NET_MDEV_TX },
};

static void vfio_print_fail(unsigned int reason)
{
	if (reason > ARRAY_SIZE(vfio_fail_str))
		printf("Unknown\n");
	else
		printf("%s\n", vfio_fail_str[reason]);
}

/**
 * returns a valid VFIO container
 * fd must be closed by caller
 */
int get_container(void)
{
	int ret;
	int container;
	/* Create a new container */
	container = open("/dev/vfio/vfio", O_RDWR);

	if (container < 0)
		return container;

	ret = ioctl(container, VFIO_GET_API_VERSION);
	if (ret != VFIO_API_VERSION) {
		printf("Unknown API version\n");
		goto out;
	}

	if (!ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		printf("Doesn't support the IOMMU driver we want\n");
		goto out;
	}

	return container;
out:
	close(container);
	container = -1;
	return ret;

}

/**
 * returns a valid VFIO group
 * fd must be close by caller
 */
int get_group(int grp_id)
{
	char path[64];
	int ret;
	int group;
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };

	snprintf(path, sizeof(path), "/dev/vfio/%d", grp_id);
	group = open(path, O_RDWR);
	if (group < 0) {
		printf("Failed to open %s, %d (%s)\n",
		       path, group, strerror(errno));
		return group;
	}

	ret = ioctl(group, VFIO_GROUP_GET_STATUS, &group_status);

	if (ret < 0) {
		printf("ioctl(VFIO_GROUP_GET_STATUS) failed\n");
		goto out;
	}

	/* Test the group is viable and available */
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		printf("Group is not viable\n");
		goto out;
	}

	return group;
out:
	close(group);
	group = -1;
	return ret;
}

static int vfio_match_caps(struct vfio_info_cap_header *hdr, __u32 type,
			   __u32 subtype)
{
	struct vfio_region_info_cap_type *cap_type;

	cap_type = odp_container_of(hdr, struct vfio_region_info_cap_type, header);

	return !(cap_type->type == type && cap_type->subtype == subtype);
}

static int vfio_find_sparse_mmaps(struct vfio_info_cap_header *hdr,
				  struct vfio_region_info_cap_sparse_mmap **sparse)
{
	*sparse = odp_container_of(hdr, struct vfio_region_info_cap_sparse_mmap, header);

	return 0;
}


static struct vfio_info_cap_header *vfio_get_region_info_cap(struct vfio_region_info *info,
							     __u16 id)
{
	struct vfio_info_cap_header *hdr;
	void *ptr = info;

	if (!(info->flags & VFIO_REGION_INFO_FLAG_CAPS))
		return NULL;

	for (hdr = (struct vfio_info_cap_header *)(char *)ptr + info->cap_offset; hdr != ptr; hdr = (struct vfio_info_cap_header *)(char *)ptr + hdr->next) {
		if (hdr->id == id)
			return hdr;
	}

	return NULL;
}

static int vfio_get_region_sparse_mmaps(int device, struct vfio_region_info *region_info)
{
	struct vfio_region_info *info;
	struct vfio_info_cap_header *caps = NULL;
	struct vfio_region_info_cap_sparse_mmap *sparse;
	int ret = 0;
	unsigned int i;

	if (region_info->flags & VFIO_REGION_INFO_FLAG_CAPS &&
	    region_info->argsz > sizeof(*region_info)) {
		info = calloc(1, region_info->argsz);
		if (!info)
			return -EINVAL;
		memcpy(info, region_info, region_info->argsz);
		ret = ioctl(device, VFIO_DEVICE_GET_REGION_INFO, info);
		if (ret < 0) {
			free(info);
			info = NULL;
			return -EINVAL;
		}
		caps = vfio_get_region_info_cap(info, VFIO_REGION_INFO_CAP_SPARSE_MMAP);
		free(info);
		info = NULL;
		if (!caps)
			ret = -ENODEV;
		ret = vfio_find_sparse_mmaps(caps, &sparse);
		for (i = 0; i < sparse->nr_areas; i++)
			printf("Sparse region: %d 0x%llx %llu\n", i,
			       sparse->areas[i].offset, sparse->areas[i].size);
	}

	return ret;
}

static int vfio_get_region_cap_type(int device, struct vfio_region_info *region_info)
{
	struct vfio_info_cap_header *caps = NULL;
	struct vfio_region_info *info;
	int ret = 0;
	int extra_region;

	extra_region = region_info->index - VFIO_PCI_NUM_REGIONS;
	if (region_info->flags & VFIO_REGION_INFO_FLAG_CAPS &&
	    region_info->argsz > sizeof(*region_info)) {
		info = calloc(1, region_info->argsz);
		if (!info)
			return -EINVAL;
		memcpy(info, region_info, region_info->argsz);
		ret = ioctl(device, VFIO_DEVICE_GET_REGION_INFO, info);
		if (ret < 0) {
			free(info);
			info = NULL;
			return -EINVAL;
		}
		caps = vfio_get_region_info_cap(info, VFIO_REGION_INFO_CAP_TYPE);
		free(info);
		info = NULL;
		if (!caps)
			ret = -ENODEV;
		ret = vfio_match_caps(caps, tmatch[extra_region].type,
				      tmatch[extra_region].subtype);
	}

	return ret;
}

/**
 * Get specific region info
 */
int vfio_get_region(int device, struct vfio_region_info *region_info,
		    __u32 region)
{
	int ret;
	__u16 id = VFIO_REGION_INFO_CAP_TYPE;

	region_info->index = region;
	ret = ioctl(device, VFIO_DEVICE_GET_REGION_INFO, region_info);
	printf("Region:%d ", region);
	if (ret < 0) {
		vfio_print_fail(VFIO_DEVICE_GET_REGION_INFO);
		return ret;
	}

	if (!region_info->size) {
		printf("unimplemented PCI BAR\n");
		return -EINVAL;
	}
	/*  FIXME call proper function and id, Rx/Tx descriptors are types
	 * BAR regions are sparse mmaps
	 */
	if (id == VFIO_REGION_INFO_CAP_TYPE)
		ret = vfio_get_region_cap_type(device, region_info);
	else if (id == VFIO_REGION_INFO_CAP_SPARSE_MMAP)
		ret = vfio_get_region_sparse_mmaps(device, region_info);

	return ret;
}

/**
 * mmap a PCI region
 */
void *vfio_mmap_region(int device, __u32 region, size_t *len)
{
	int ret;
	struct vfio_region_info region_info = { .argsz = sizeof(region_info) };
	void *mapped;

	ret = vfio_get_region(device, &region_info, region);
	/* api returns -EINVAL for unimplemented bars */
	if (!region_info.size || ret)
		return NULL;

	printf("region:%d size %lu, offset 0x%lx, flags 0x%x\n", region,
	       (unsigned long)region_info.size,
	       (unsigned long)region_info.offset, region_info.flags);
	if (!(region_info.flags & VFIO_REGION_INFO_FLAG_MMAP))
		return NULL;

	mapped = mmap(NULL, region_info.size, PROT_READ | PROT_WRITE,
		      MAP_SHARED, device, region_info.offset);
	if (mapped == MAP_FAILED) {
		printf("mmap failed\n");
		return NULL;
	}
	*len = region_info.size;

	return mapped;
}

/**
 * allocate portion of the 4GB space reserved by iomem_init()
 */
int iomem_alloc_dma(int device, void **iomem_current,
		    struct iomem *iomem)
{
	void *tmp;
	int ret;
	struct vfio_iommu_type1_dma_map dma_map;

	if (iomem->size >= 32 * 1024 * 1024)
		return -EINVAL;
	if ((iomem->size & 0xFFF) != 0)
		return -EINVAL; /* size should be a 4K aligned quantity */

	memset(&dma_map, 0, sizeof(dma_map));
	dma_map.argsz = sizeof(dma_map);
	/* get a portion of the 4GB window created at init time */
	tmp = mmap(*iomem_current, iomem->size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1,
		   0);
	if (tmp == MAP_FAILED)
		return -ENOMEM;

	*iomem_current = (char *)*iomem_current + iomem->size;

	iomem->vaddr = tmp;

	dma_map.vaddr = (__u64)iomem->vaddr;
	dma_map.size = iomem->size;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	/* kernel driver fills dma_map.iova with the proper allocated IOVA */
	ret = ioctl(device, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret < 0)
		return -ENOMEM;
	iomem->iova = dma_map.iova;

	printf("iomem_alloc: VA(%p) -> physmem(%lluKB) <- IOVA(%llx)\n",
	       iomem->vaddr, iomem->size / 1024, iomem->iova);

	return 0;
}

/**
 * Initialize VFIO variables.
 * set IOMMU and get device regions
 */
int vfio_init_dev(int grp, int container, struct vfio_group_status *grp_status,
		  struct vfio_iommu_type1_info *iommu_info,
		  struct vfio_device_info *dev_info, char *grp_uuid)
{
	int ret;
	int device = -1;

	ret = ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU);
	if (ret < 0) {
		vfio_print_fail(VFIO_CHECK_EXTENSION);
		goto out;
	}

	/* Test the group is viable and available */
	ret = ioctl(grp, VFIO_GROUP_GET_STATUS, grp_status);
	if (ret < 0 || !(grp_status->flags & VFIO_GROUP_FLAGS_VIABLE)) {
		vfio_print_fail(VFIO_GROUP_GET_STATUS);
		goto out;

	}

	ret = ioctl(grp, VFIO_GROUP_SET_CONTAINER, &container);
	if (ret < 0) {
		vfio_print_fail(VFIO_GROUP_SET_CONTAINER);
		printf("Failed to set group container\n");
		goto out;
	}

	ret = ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
	if (ret < 0) {
		vfio_print_fail(VFIO_SET_IOMMU);
		goto out;
	}

	ret = ioctl(container, VFIO_IOMMU_GET_INFO, iommu_info);
	if (ret < 0) {
		vfio_print_fail(VFIO_IOMMU_GET_INFO);
		goto out;
	}

	printf("iova_pgsizes bitmask=0x%llx\n", iommu_info->iova_pgsizes);
	/* Get a file descriptor for the device */
	device = ioctl(grp, VFIO_GROUP_GET_DEVICE_FD, grp_uuid);
	if (device < 0) {
		vfio_print_fail(VFIO_GROUP_GET_DEVICE_FD);
		goto out;
	}

	/* Test and setup the device */
	ret = ioctl(device, VFIO_DEVICE_GET_INFO, dev_info);
	if (ret < 0) {
		vfio_print_fail(VFIO_DEVICE_GET_INFO);
		goto out;
	}

	printf("Device %d Regions: %d, irqs:%d\n", device,
	       dev_info->num_regions, dev_info->num_irqs);
out:
	return device;
}
