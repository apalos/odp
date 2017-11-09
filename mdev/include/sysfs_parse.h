#ifndef _SYSFS_PARSE_H
#define _SYSFS_PARSE_H

#define NET_MDEV_PREFIX "mdev:"

int mdev_sysfs_discover(const char *mod_name, const char *if_name, char *uuid,
			size_t sz);

#endif
