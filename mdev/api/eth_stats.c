#include <odp_posix_extensions.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>

#include <odp_debug_internal.h>

#include <eth_stats.h>

/** Simple method for getting link status
 * No root access needed
 */
int mdev_get_iff_link(char *ifname)
{
	const short flags = IFF_UP | IFF_RUNNING;

	int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq if_req;
	int ret;

	if (sockfd < 0) {
		ODP_ERR("Socket failed. Errno = %d\n", errno);
		return -1;
	}

	strncpy(if_req.ifr_name, ifname, sizeof(if_req.ifr_name));
	ret = ioctl(sockfd, SIOCGIFFLAGS, &if_req);
	close(sockfd);

	if (ret < 0)  {
		ODP_ERR("ioctl failed. Errno = %d\n", errno);
		return -1;
	}

	return (if_req.ifr_flags & flags) == flags;
}
