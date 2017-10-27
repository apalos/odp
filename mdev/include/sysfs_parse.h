#ifndef _SYSFS_PARSE_H
#define _SYSFS_PARSE_H

#define NET_MDEV_MATCH "mdev:"
#define R8169_MOD_NAME "r8169"

int mdev_sysfs_discover(const char *netdev, char *uuid, size_t sz);

#endif
