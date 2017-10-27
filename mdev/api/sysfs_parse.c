#include <odp_posix_extensions.h>
#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>

#include <sysfs_parse.h>

static int mdev_check_path(const char *check_path)
{
	size_t len = strlen(check_path);
	char path[len + 2];

	snprintf(path, sizeof(path), "%s/", check_path);

	return access(path, F_OK);
}

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

	if (mdev_check_path((const char *) path))
		return -1;

	len = readlink(path, link, linksz -1);
	if (len != -1) {
		link[len] = '\0';
		return 0;
	}
	return -1;
}

static int mdev_get_names(const char *netdev, char *driver, size_t sz)
{
	if (strncmp(netdev, NET_MDEV_MATCH, strlen(NET_MDEV_MATCH)))
		return -1;

	strncpy(driver, netdev + strlen(NET_MDEV_MATCH), sz);

	return 0;
}

/**
 * returns group_id or -1 on fail and fills group_uuid
 */
int mdev_sysfs_discover(const char *netdev, char *uuid, size_t sz)
{
	int ret;
	char ifname[64];
	char *driver, *iommu_group;
	char sysfs_path[2048], sysfs_link[2048];
	DIR *dir;
	struct dirent *dp;

	memset(ifname, 0, sizeof(ifname));

	ret = mdev_get_names(netdev, ifname, sizeof(ifname));
	if (ret)
		return -1;

	/* Don't put / on the end of the path */
	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s/device/driver",
		 ifname);
	ret = mdev_readlink(sysfs_path, sysfs_link, sizeof(sysfs_link));
	if (ret) {
		printf("Can't locate sysfs driver path\n");
		return -1;
	}

	driver = mdev_basename(sysfs_link);
	if (!driver) {
		printf("Can't driver in sysfs\n");
		return -1;
	}

	if (strcmp(driver, R8169_MOD_NAME)) {
		printf("Invalid driver name\n");
		return -1;
	}

	snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/net/%s/device/mdev_supported_types/%s-netmdev/devices/",
		 ifname, driver);
	dir = opendir(sysfs_path);
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
		printf("Can't locate IOMMU sysfs path\n");
		return -1;
	}

	iommu_group = mdev_basename(sysfs_link);
	if (!iommu_group) {
		printf("Can't locate iommu group in sysfs\n");
		return -1;
	}
	ret = atoi(iommu_group);

	return ret;
}
