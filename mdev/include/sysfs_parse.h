#ifndef _SYSFS_PARSE_H
#define _SYSFS_PARSE_H

#define NET_MDEV_MATCH "mdev:"

int mdev_sysfs_discover(const char *netdev, const char *modname, char *uuid,
			size_t sz);

#endif
