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

#include <config.h>
#include <odp_posix_extensions.h>
#include <odp/api/hints.h>

#include <common.h>
#include <uapi/net_mdev.h>
#include <vfio_api.h>
#include <sysfs_parse.h>

#include <odp_debug_internal.h>
#include <odp_align_internal.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
static const char *vfio_fail_str[] = {
	[VFIO_CHECK_EXTENSION] = "Doesn't support the IOMMU driver we want",
	[VFIO_GROUP_GET_STATUS] = "Can't get status",
	[VFIO_GROUP_SET_CONTAINER] = "Failed to set container",
	[VFIO_SET_IOMMU] = "Failed to set IOMMU",
	[VFIO_IOMMU_GET_INFO] = "Failed to get IOMMU info",
	[VFIO_GROUP_GET_DEVICE_FD] = "Failed to get device FD",
	[VFIO_DEVICE_GET_INFO] = "Failed to get device info",
	[VFIO_DEVICE_GET_REGION_INFO] = "Failed to get PCI region info",
};

static void vfio_print_fail(unsigned int reason)
{
	if (reason > ARRAY_SIZE(vfio_fail_str))
		ODP_ERR("Unknown\n");
	else
		ODP_ERR("%s\n", vfio_fail_str[reason]);
}

/**
 * returns a valid VFIO container
 * fd must be closed by caller
 */
static int get_container(void)
{
	int ret;
	int container;
	/* Create a new container */
	container = open("/dev/vfio/vfio", O_RDWR);

	if (container < 0)
		return container;

	ret = ioctl(container, VFIO_GET_API_VERSION);
	if (ret != VFIO_API_VERSION) {
		ODP_ERR("Unknown API version\n");
		goto out;
	}

	if (!ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
		ODP_ERR("Doesn't support the IOMMU driver we want\n");
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
static int get_group(int grp_id)
{
	char path[64];
	int ret;
	int group;
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };

	snprintf(path, sizeof(path), "/dev/vfio/%d", grp_id);
	group = open(path, O_RDWR);
	if (group < 0) {
		ODP_ERR("Failed to open %s, %d (%s)\n",
		       path, group, strerror(errno));
		return group;
	}

	ret = ioctl(group, VFIO_GROUP_GET_STATUS, &group_status);

	if (ret < 0) {
		ODP_ERR("ioctl(VFIO_GROUP_GET_STATUS) failed\n");
		goto out;
	}

	/* Test the group is viable and available */
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		ODP_ERR("Group is not viable\n");
		goto out;
	}

	return group;
out:
	close(group);
	group = -1;
	return ret;
}

static void vfio_find_sparse_mmaps(struct vfio_info_cap_header *hdr,
				  struct vfio_region_info_cap_sparse_mmap **sparse)
{
	*sparse = odp_container_of(hdr, struct vfio_region_info_cap_sparse_mmap, header);
}


static struct vfio_info_cap_header *vfio_get_region_info_cap(struct vfio_region_info *info,
							     __u16 id)
{
	struct vfio_info_cap_header *hdr;
	void *ptr = info;

	if (!(info->flags & VFIO_REGION_INFO_FLAG_CAPS))
		return NULL;

	for (hdr = (struct vfio_info_cap_header *)((char *)ptr + info->cap_offset);
	     hdr != ptr; hdr = (struct vfio_info_cap_header *)((char *)ptr + hdr->next)) {
		if (hdr->id == id)
			return hdr;
	}

	return NULL;
}

static struct vfio_info_cap_header *vfio_get_cap_info(struct vfio_region_info *region_info,
						      __u16 id)
{
	struct vfio_info_cap_header *caps = NULL;

	caps = vfio_get_region_info_cap(region_info, id);

	return caps;
}

int vfio_get_region_sparse_mmaps(struct vfio_region_info *region_info,
				 struct vfio_region_info_cap_sparse_mmap **sparse)
{
	struct vfio_info_cap_header *caps = NULL;
	int ret = -ENOENT;

	if (region_info->flags & VFIO_REGION_INFO_FLAG_CAPS &&
	    region_info->argsz > sizeof(*region_info)) {
		caps = vfio_get_cap_info(region_info,
					 VFIO_REGION_INFO_CAP_SPARSE_MMAP);
		if (!caps)
			goto out;
		vfio_find_sparse_mmaps(caps, sparse);
		if (*sparse) {
			for (uint32_t i = 0; i < (*sparse)->nr_areas; i++)
				ODP_DBG("Sparse region: %d 0x%llx %llu\n", i,
				(*sparse)->areas[i].offset, (*sparse)->areas[i].size);
		}

		ret = 0;
	}

out:
	return ret;
}

/** Match capability type
 * returns 0 on succcess
 */
int vfio_get_region_cap_type(struct vfio_region_info *region_info,
			     mdev_region_class_t *class_info)
{
	struct vfio_info_cap_header *caps = NULL;
	int ret = 0;
	struct vfio_region_info_cap_type *cap_type;

	if (region_info->flags & VFIO_REGION_INFO_FLAG_CAPS &&
	    region_info->argsz > sizeof(*region_info)) {
		caps = vfio_get_cap_info(region_info,
					 VFIO_REGION_INFO_CAP_TYPE);
		if (!caps) {
			ret = -EINVAL;
			goto out;
		}

		cap_type = odp_container_of(caps, struct vfio_region_info_cap_type, header);
		class_info->type = cap_type->type;
		class_info->subtype = cap_type->subtype;
	}
out:
	return ret;
}

/**
 * Get specific region info
 */
static struct vfio_region_info *vfio_get_region(mdev_device_t *mdev, __u32 region)
{
	int ret;
	struct vfio_region_info *region_info = NULL;

	ODP_DBG("Region:%d\n", region);
	region_info = calloc(1, sizeof(*region_info));
	if (!region_info)
		goto out;

	region_info->index = region;
	region_info->argsz = sizeof(*region_info);
	ret = ioctl(mdev->device, VFIO_DEVICE_GET_REGION_INFO, region_info);
	if (ret < 0 || !region_info->size) {
		vfio_print_fail(VFIO_DEVICE_GET_REGION_INFO);
		goto out;
	}

	if (region_info->argsz > sizeof(*region_info)) {
		region_info = realloc(region_info, region_info->argsz);
		ODP_DBG("region info %d with extended capabilities size: %u\n",
			region, region_info->argsz);
		ret = ioctl(mdev->device, VFIO_DEVICE_GET_REGION_INFO, region_info);
		if (ret < 0 || !region_info->size) {
			vfio_print_fail(VFIO_DEVICE_GET_REGION_INFO);
			goto out;
		}
	}

	return region_info;
out:
	if (region_info)
		free(region_info);
	return NULL;
}

/**
 * mmap a VFIO region
 */
void *mdev_region_mmap(mdev_device_t *mdev, uint64_t offset, uint64_t size)
{
	void *addr;

	/* Make sure we're page aligned */
	ODP_ASSERT(offset == ROUNDUP_ALIGN(offset, ODP_PAGE_SIZE));
	ODP_ASSERT(size == ROUNDUP_ALIGN(size, ODP_PAGE_SIZE));

	if (mdev->mappings_count >= ARRAY_SIZE(mdev->mappings))
		return MAP_FAILED;

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    mdev->device, offset);
	if (addr == MAP_FAILED)
		return addr;

	mdev->mappings[mdev->mappings_count].addr = addr;
	mdev->mappings[mdev->mappings_count].size = size;
	mdev->mappings_count++;

	return addr;
}

/**
 * allocate portion of the 4GB space reserved by iomem_init()
 */
int iomem_alloc_dma(mdev_device_t *mdev, struct iomem *iomem)
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
	tmp = mmap(mdev->iocur, iomem->size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1,
		   0);
	if (tmp == MAP_FAILED)
		return -ENOMEM;

	mdev->iocur += iomem->size;

	iomem->vaddr = tmp;

	dma_map.vaddr = (__u64)iomem->vaddr;
	dma_map.size = iomem->size;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	/* kernel driver fills dma_map.iova with the proper allocated IOVA */
	ret = ioctl(mdev->device, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (ret < 0)
		return -ENOMEM;
	iomem->iova = dma_map.iova;

	ODP_DBG("iomem_alloc: VA(%p) -> physmem(%lluKB) <- IOVA(%llx)\n",
	       iomem->vaddr, iomem->size / 1024, iomem->iova);

	return 0;
}

int iomem_free_dma(mdev_device_t *mdev, struct iomem *iomem)
{
	struct vfio_iommu_type1_dma_unmap dma_unmap;
	int ret;

	memset(&dma_unmap, 0, sizeof(dma_unmap));
	dma_unmap.argsz = sizeof(dma_unmap);
	dma_unmap.iova = iomem->iova;
	dma_unmap.size = iomem->size;
	dma_unmap.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	ret = ioctl(mdev->device, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	if (ret < 0) {
		ODP_ERR("iomem_free: unmap failed\n");
		return -EFAULT;
	}

	ret = munmap(iomem->vaddr, iomem->size);
	if (ret) {
		ODP_ERR("munmap failed\n");
		return -EFAULT;
	}

	return 0;
}

/**
 * Initialize VFIO variables.
 * set IOMMU and get device regions
 */
static int vfio_init_dev(int grp, int container,
			 struct vfio_group_status *grp_status,
			 struct vfio_iommu_type1_info *iommu_info,
			 struct vfio_device_info *dev_info, char *grp_uuid)
{
	int device = -1;
	int ret;

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

	ODP_DBG("iova_pgsizes bitmask=0x%llx\n", iommu_info->iova_pgsizes);
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

	ODP_DBG("Device %d Regions: %d, irqs:%d\n", device,
	       dev_info->num_regions, dev_info->num_irqs);

out:
	return device;
}

int mdev_device_create(mdev_device_t *mdev, const char *mod_name,
		       const char *if_name,
		       mdev_region_info_cb_t region_info_cb)
{
	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status)
	};
	struct vfio_iommu_type1_info iommu_info = {
		.argsz = sizeof(iommu_info)
	};
	struct vfio_device_info device_info = {
		.argsz = sizeof(device_info)
	};
	int ret;

	memset(mdev, 0, sizeof(*mdev));
	mdev->container = -1;
	mdev->group = -1;

	strncpy(mdev->if_name, if_name, sizeof(mdev->if_name) - 1);

	mdev->group_id =
	    mdev_sysfs_discover(mod_name, mdev->if_name, mdev->group_uuid,
				sizeof(mdev->group_uuid));
	if (mdev->group_id < 0)
		goto fail;

	/* FIXME iobase and container(probably) has to be done globally and not per driver */
	mdev->iobase = iomem_init();
	if (!mdev->iobase)
		goto fail;

	mdev->iocur = mdev->iobase;

	mdev->container = get_container();
	if (mdev->container < 0)
		goto fail;

	mdev->group = get_group(mdev->group_id);
	if (mdev->group < 0)
		goto fail;

	mdev->device =
	    vfio_init_dev(mdev->group, mdev->container, &group_status,
			  &iommu_info, &device_info, mdev->group_uuid);
	if (mdev->device < 0)
		goto fail;

	ret = -EINVAL;
	for (uint32_t region = 0; region < device_info.num_regions; region++) {
		struct vfio_region_info *region_info;

		region_info = vfio_get_region(mdev, region);
		if (!region_info)
			continue;

		ret = region_info_cb(mdev, region_info);
		if (ret < 0) {
			ODP_ERR("Region info cb fail on region_info[%u]\n",
				region);
			return -1;
		}

		free(region_info);
		region_info = NULL;
		ret = 0;
	}

	return ret;

fail:
	return -1;
}

void mdev_device_destroy(mdev_device_t *mdev)
{
	if (mdev->group != -1)
		close(mdev->group);
	if (mdev->container != -1)
		close(mdev->container);
	if (mdev->iobase)
		iomem_free(mdev->iobase);

	for (uint16_t i = 0; i < mdev->mappings_count; i++)
		munmap(mdev->mappings[i].addr, mdev->mappings[i].size);
}

int mdev_attr_get(mdev_device_t *mdev, const char *attr, char *buf)
{
	char sysfs_path[2048];

	snprintf(sysfs_path, sizeof(sysfs_path) - 1, "/sys/class/net/%s/%s",
		 mdev->if_name, attr);
	sysfs_path[sizeof(sysfs_path) - 1] = '\0';

	return mdev_sysfs_attr_get(sysfs_path, buf);
}

int mdev_attr_u64_get(mdev_device_t *mdev, const char *attr, uint64_t *val)
{
	char buf[ODP_PAGE_SIZE];
	char *endptr;

	if (mdev_attr_get(mdev, attr, buf) < 0)
		return -1;

	if (*buf == '\0')
		return -1;

	*val = strtoull(buf, &endptr, 0);
	if (*endptr != '\0')
		return -1;

	return 0;
}

int mdev_attr_u32_get(mdev_device_t *mdev, const char *attr, uint32_t *val)
{
	uint64_t raw;

	if (mdev_attr_u64_get(mdev, attr, &raw) < 0)
		return -1;

	if (raw > UINT32_MAX)
		return -1;

	*val = raw;

	return 0;
}

int mdev_attr_u16_get(mdev_device_t *mdev, const char *attr, uint16_t *val)
{
	uint64_t raw;

	if (mdev_attr_u64_get(mdev, attr, &raw) < 0)
		return -1;

	if (raw > UINT16_MAX)
		return -1;

	*val = raw;

	return 0;
}

int mdev_attr_u8_get(mdev_device_t *mdev, const char *attr, uint8_t *val)
{
	uint64_t raw;

	if (mdev_attr_u64_get(mdev, attr, &raw) < 0)
		return -1;

	if (raw > UINT8_MAX)
		return -1;

	*val = raw;

	return 0;
}
