#include <odp_posix_extensions.h>
#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>

#include <config.h>
#include <odp_debug_internal.h>

#include <sysfs_parse.h>

static char *mdev_basename(char *path)
{
	char *rpath;

	rpath = basename(path);
	if (rpath)
		return rpath;

	return NULL;
}

static int mdev_readlink(const char *path, char *link, size_t linksz)
{
	ssize_t len;

	len = readlink(path, link, linksz -1);
	if (len != -1) {
		link[len] = '\0';
		return 0;
	}
	return -1;
}

/**
 * returns group_id or -1 on fail and fills group_uuid
 */
int mdev_sysfs_discover(const char *mod_name, const char *if_name, char *uuid,
			size_t sz)
{
	int ret;
	char *driver, *iommu_group;
	char sysfs_path[2048], sysfs_link[2048];
	DIR *dir;
	struct dirent *dp;

	/* Don't put / on the end of the path */
	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s/device/driver",
		 if_name);
	ret = mdev_readlink(sysfs_path, sysfs_link, sizeof(sysfs_link));
	if (ret) {
		ODP_ERR("Can't locate sysfs driver path\n");
		return -1;
	}

	driver = mdev_basename(sysfs_link);
	if (!driver) {
		ODP_ERR("Can't driver in sysfs\n");
		return -1;
	}

	if (strcmp(driver, mod_name)) {
		ODP_ERR("Invalid driver name\n");
		return -1;
	}

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s/device/mdev_supported_types/%s-netmdev/devices/",
		 if_name, driver);
	dir = opendir(sysfs_path);
	if (!dir)
		return -1;
	/* FIXME only the last uuid will be returned now */
	while ((dp = readdir(dir))) {
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		else
			strncpy(uuid, dp->d_name, sz);
	}
	closedir(dir);

	if (!uuid[0])
		return -1;

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/bus/mdev/devices/%s/iommu_group",
		 uuid);
	ret = mdev_readlink(sysfs_path, sysfs_link, sizeof(sysfs_link));
	if (ret) {
		ODP_ERR("Can't locate IOMMU sysfs path\n");
		return -1;
	}

	iommu_group = mdev_basename(sysfs_link);
	if (!iommu_group) {
		ODP_ERR("Can't locate iommu group in sysfs\n");
		return -1;
	}
	ret = atoi(iommu_group);

	return ret;
}
