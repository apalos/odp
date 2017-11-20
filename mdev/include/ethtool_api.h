#ifndef _ETHTOOL_API_H
#define _ETHTOOL_API_H

#include <linux/ethtool.h>

int mdev_ringparam_get(mdev_device_t *mdev, struct ethtool_ringparam *ering);
#endif
