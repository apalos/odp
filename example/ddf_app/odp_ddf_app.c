/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>

#include <example_debug.h>
#include <odp_api.h>
#include <odp_drv.h>
#include <odp/helper/odph_api.h>

#define POOL_NUM_PKT           2048  /* Number of packets in packet pool */
#define POOL_PKT_LEN           1856  /* Max packet length */

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odp_pktio_t pktio = ODP_PKTIO_INVALID;
	odp_pool_param_t params;
	odp_pool_t pool = ODP_POOL_INVALID;

	if (argc == 1 || argc > 2) {
		printf("Error: invalid parameter.\nUsage:\n\t%s <interface>\n", argv[0]);
		exit(0);
	}

	EXAMPLE_DBG("Start DDF Application...\n");

	/* Initialize ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = POOL_PKT_LEN;
	params.pkt.len     = POOL_PKT_LEN;
	params.pkt.num     = POOL_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	/* Open pktio*/
	pktio = odp_pktio_open(argv[1], pool, NULL);
	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ERR("Error: Failed to open pktio \"%s\".\n", argv[1]);

	/* Close pktio*/
	if (odp_pktio_close(pktio))
		EXAMPLE_ERR("Error: Failed to close pktio \"%s\".\n", argv[1]);

	if (odp_pool_destroy(pool))
		EXAMPLE_ERR("Error: Failed to destroy packet pool\n");

	/* Print ddf objects*/
	odpdrv_print_all();

	/* Terminate ODP */
	odp_term_local();
	odp_term_global(instance);

	EXAMPLE_DBG("Exit DDF Application.\n");
	return 0;
}
