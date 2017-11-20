#include <odp_posix_extensions.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <linux/sockios.h>
#include <linux/ethtool.h>

#include <vfio_api.h>
#include <ethtool_api.h>

static int send_ioctl(int fd, void *cmd, char *if_name)
{
	struct ifreq ifr;
	ifr.ifr_data = cmd;
	strcpy((void *)&ifr.ifr_name, if_name);

	return ioctl(fd, SIOCETHTOOL, &ifr);
}

int mdev_ringparam_get(mdev_device_t *mdev, struct ethtool_ringparam *ering)
{

	int fd, err;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -EINVAL;

	ering->cmd = ETHTOOL_GRINGPARAM;
	err = send_ioctl(fd, &ering, mdev->if_name);
	close(fd);

	return err;
}
