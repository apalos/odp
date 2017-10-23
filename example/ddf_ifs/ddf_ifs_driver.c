/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include "odp_drv.h"
#include <odp_packet_io_internal.h>
#include "ddf_ifs_api.h"
#include "ddf_ifs_driver.h"

#define DDF_IFS_NAME_SIZE 50
#define DDF_IFS_DEV_PREFIX "ddf_ifs:"
#define DDF_IFS_DEV_PREFIX_LEN 8
/** Packet socket using netmap mmaped rings for both Rx and Tx */
typedef struct {
	char dev_name[DDF_IFS_NAME_SIZE];	/**< interface name */
} pktio_ops_ddf_ifs_data_t;


static odpdrv_driver_t ddf_ifs_driver;
static int drv_data = 12;

static int ddf_ifs_driver_probe(odpdrv_device_t dev, odpdrv_devio_t devio,
				int devio_idx)
{
	printf("%s(dev, devio, devio_idx = %d)\n", __func__, devio_idx);

	(void)devio;

	odpdrv_device_set_data(dev, (void *)&drv_data);

	return 0;
}

static int ddf_ifs_driver_unbind(odpdrv_device_t dev,
				 void (*callback)(odpdrv_device_t dev),
				 uint32_t flags)
{
	printf("%s()\n", __func__);

	if (!(flags & ODPDRV_DRV_UNBIND_IMMEDIATE))
		return -1; /* unsupported*/

	callback(dev);

	return 0;
}

static int ddf_ifs_driver_remove(void)
{
	printf("%s()\n", __func__);

	return 0;
}

static int ddf_ifs_init_global(void)
{
	printf("%s()\n", __func__);
	return 0;
}
static int ddf_ifs_term_global(void)
{
	printf("%s()\n", __func__);
	return 0;
}

static int ddf_ifs_open(odp_pktio_t pktio ODP_UNUSED, pktio_entry_t *pktio_entry,
		    const char *devname, odp_pool_t pool)
{
	pktio_ops_ddf_ifs_data_t *pkt_ddf_ifs = odp_ops_data(pktio_entry, ddf_ifs);

	(void)pktio;
	(void)pool;

	printf("%s(%s)\n", __func__, devname);
	if (strncmp(devname, DDF_IFS_DEV_PREFIX, DDF_IFS_DEV_PREFIX_LEN) == 0)
		devname += DDF_IFS_DEV_PREFIX_LEN;
	else
		return -1;

	strcpy(pkt_ddf_ifs->dev_name, devname);
	printf("%s() - device %s oppened!!!\n", __func__,
	       pkt_ddf_ifs->dev_name);
	return 0;
}

static int ddf_ifs_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_ddf_ifs_data_t *pkt_ddf_ifs = odp_ops_data(pktio_entry, ddf_ifs);

	printf("%s() - device %s closed.\n", __func__, pkt_ddf_ifs->dev_name);

	return 0;
}

static pktio_ops_module_t ddf_ifs_pktio_ops = {
	.base = {
		.name = "ddf_ifs",
		.init_local = NULL,
		.term_local = NULL,
		.init_global = ddf_ifs_init_global,
		.term_global = ddf_ifs_term_global,
	},
	.open = ddf_ifs_open,
	.close = ddf_ifs_close,
	.start = NULL/*ddf_ifs_start*/,
	.stop = NULL/*ddf_ifs_stop*/,
	.stats = NULL/*ddf_ifs_stats*/,
	.stats_reset = NULL/*ddf_ifs_stats_reset*/,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.recv = NULL/*ddf_ifs_recv*/,
	.send = NULL/*ddf_ifs_send*/,
	.mtu_get = NULL/*ddf_ifs_mtu_get*/,
	.promisc_mode_set = NULL/*ddf_ifs_promisc_mode_set*/,
	.promisc_mode_get = NULL/*ddf_ifs_promisc_mode_get*/,
	.mac_get = NULL/*ddf_ifs_mac_addr_get*/,
	.link_status = NULL/*ddf_ifs_link_status*/,
	.capability = NULL/*ddf_ifs_capability*/,
	.config = NULL,
	.input_queues_config = NULL/*ddf_ifs_input_queues_config*/,
	.output_queues_config = NULL/*ddf_ifs_output_queues_config*/,
	.print = NULL/*ddf_ifs_print*/,
};

int register_driver(void)
{
/* Register ddf driver*/
	odpdrv_driver_param_t param = {
		.name = DDF_IFS_DRV_NAME,
		.devios = {{DDF_IFS_DEVIO_API_NAME, DDF_IFS_DEVIO_API_VER},
				   {"", 0}, {"", 0} },
		.probe = ddf_ifs_driver_probe,
		.unbind = ddf_ifs_driver_unbind,
		.remove = ddf_ifs_driver_remove,
		};

	printf("\t%s()\n", __func__);

	ddf_ifs_driver = odpdrv_driver_register(&param);
	if (ODPDRV_DRIVER_INVALID == ddf_ifs_driver) {
		printf("Error: Failed to %s()\n", __func__);
		return -1;
	}

/* Register pktio_ops module*/
	odp_module_constructor(&ddf_ifs_pktio_ops);

	odp_subsystem_register_module(pktio_ops, &ddf_ifs_pktio_ops);

/* Explicit call to Init global*/
	ddf_ifs_init_global();
	return 0;
}
