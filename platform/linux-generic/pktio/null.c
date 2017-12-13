/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_posix_extensions.h>

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/packet.h>

#include <odp_packet_io_internal.h>
#include <odp_debug_internal.h>
#include <protocols/eth.h>

#include <sys/ioctl.h>
#include <poll.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <pktio/ethtool.h>
#include <pktio/common.h>

#include <inttypes.h>

typedef struct {
	odp_pktio_capability_t capa;	/**< interface capabilities */
} pktio_ops_null_data_t;

static int null_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		       const char *resource, odp_pool_t pool ODP_UNUSED)
{
	pktio_ops_null_data_t *pkt_null = odp_ops_data(pktio_entry, null);

	if (strncmp(resource, "null:", 5) != 0)
		return -1;

	memset(pkt_null, 0, sizeof(*pkt_null));

	pkt_null->capa.max_input_queues = PKTIO_MAX_QUEUES;
	pkt_null->capa.max_output_queues = PKTIO_MAX_QUEUES;

	return 0;
}

static int null_close(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

static int null_recv(pktio_entry_t *pktio_entry ODP_UNUSED,
		       int index ODP_UNUSED,
		       odp_packet_t pkt_table[] ODP_UNUSED, int num ODP_UNUSED)
{
	return 0;
}

static int null_send(pktio_entry_t *pktio_entry ODP_UNUSED,
		       int index ODP_UNUSED, const odp_packet_t pkt_table[],
		       int num)
{
	odp_packet_free_multi(pkt_table, num);
	return num;
}

static int null_mac_get(pktio_entry_t *pktio_entry ODP_UNUSED, void *mac_addr)
{
	memset(mac_addr, 0xa2, ETH_ALEN);
	return ETH_ALEN;
}

static int null_link_status(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 1;
}


static int null_capability(pktio_entry_t *pktio_entry,
			     odp_pktio_capability_t *capa)
{
	pktio_ops_null_data_t *pkt_null = odp_ops_data(pktio_entry, null);

	*capa = pkt_null->capa;
	return 0;
}

static int null_input_queues_config(pktio_entry_t *pktio_entry ODP_UNUSED,
				      const odp_pktin_queue_param_t *p ODP_UNUSED)
{
	return 0;
}

static int null_output_queues_config(pktio_entry_t *pktio_entry ODP_UNUSED,
				       const odp_pktout_queue_param_t *p ODP_UNUSED)
{
	return 0;
}

static pktio_ops_module_t null_pktio_ops = {
	.base = {
		.name = "null",
	},

	.open = null_open,
	.close = null_close,

	.recv = null_recv,
	.send = null_send,

	.mac_get = null_mac_get,

	.link_status = null_link_status,

	.capability = null_capability,

	.input_queues_config = null_input_queues_config,
	.output_queues_config = null_output_queues_config,
};

ODP_MODULE_CONSTRUCTOR(null_pktio_ops)
{
	odp_module_constructor(&null_pktio_ops);
	odp_subsystem_register_module(pktio_ops, &null_pktio_ops);
}

/* Temporary variable to enable link this module,
 * will remove in Makefile scheme changes.
 */
int enable_link_null_pktio_ops = 0;
