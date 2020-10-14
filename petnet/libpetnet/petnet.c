/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <pthread.h>
#include <string.h>

#include <petlib/pet_log.h>
#include <petlib/pet_util.h>
#include <petlib/pet_file.h>

#include <core/packet.h>
#include <core/packet_pool.h>
#include <core/timer.h>
#include <core/arp.h>
#include <core/tcp.h>
#include <core/udp.h>
#include <core/socket.h>


#include <drivers/pet_driver.h>

#include <util/sys.h>

#include "petnet.h"

#define PKT_POOL_SIZE   16384

struct petnet * petnet_state = NULL;

static void 
__free_petnet_state(struct petnet * state)
{
	if (state->addr_v4)  free_ipv4_addr(state->addr_v4);
	//	if (state->addr_v6)  free_ipv6_addr(state->addr_v6);
	if (state->net_dev)  pet_free(state->net_dev);
	if (state->mac_addr) free_mac_addr(state->mac_addr);

	pet_free(state);
}

static struct petnet *
__create_petnet_state(struct ipv4_addr * addr_v4,
					  struct ipv6_addr * addr_v6,
					  char             * net_dev)
{
	struct petnet * net_state = NULL;

	net_state = pet_malloc(sizeof(struct petnet));

	if (net_state == NULL) {
		log_error("Could not allocate petnet state\n");
		goto err;
	}


	return net_state;
err:
	if (net_state) __free_petnet_state(net_state);

	return NULL;
}



struct petnet *
petnet_init(struct ipv4_addr * addr_v4,
			struct ipv6_addr * addr_v6,
			char             * net_dev)
{
	struct petnet * state = NULL;

	int ret = 0;

	state = __create_petnet_state(addr_v4, addr_v6, net_dev);

	if (state == NULL) {
		log_error("Could create petnet state\n");
		goto err;
	}

	state->pkt_pool_size = PKT_POOL_SIZE;

	state->net_dev  = strndup(net_dev, strlen(net_dev));
	state->addr_v4  = ipv4_addr_clone(addr_v4);
	//	state->addr_v6  = ipv6_addr_clone(addr_v6);
	
	ret |= tap_driver_init(state);
	ret |= pet_timer_init(state);
	ret |= arp_init(state);
	ret |= tcp_init(state);
	ret |= udp_init(state);
	ret |= socket_init(state);

	if (ret != 0) {
		log_error("Subsystem initialization failed\n");
		goto err;
	}

	state->mac_addr     = sys_get_iface_mac_addr(net_dev);
	state->device_mtu   = sys_get_iface_mtu(net_dev);


	state->debug_enable = 0;


	if ((state->addr_v4    == NULL) ||
//		(state->addr_v6    == NULL) ||
		(state->net_dev    == NULL) ||
		(state->mac_addr   == NULL) ||
		(state->device_mtu == 0)) {
		log_error("Could not initialize petnet state\n");
		goto err;
	}

	petnet_state = state;

	return state;

err:
	if (state) __free_petnet_state(state);

	return NULL;
}


struct petnet *
petnet_init_from_config(char * config_filename)
{
	struct petnet  * state = NULL;

	size_t           config_size = 0; 
	char           * config_data = NULL;
	pet_json_obj_t   config_json = PET_JSON_INVALID_OBJ;

	struct ipv4_addr * addr_v4 = NULL;
	struct ipv6_addr * addr_v6 = NULL;
	char             * net_dev = NULL;

	
	int ret = 0;

	ret = pet_read_file(config_filename, (uint8_t **)&config_data, &config_size);

	if (ret != 0) {
		log_error("Could not read config file (%s)\n", config_filename);
		goto err;
	}

	config_json = pet_json_parse_str(config_data);

	if (config_json == PET_JSON_INVALID_OBJ) {
		log_error("Could not parse config JSON\n");
		goto err;
	}


	addr_v4 = ipv4_addr_from_json(config_json, "ipv4_address");
	addr_v6 = NULL;

	ret = pet_json_get_string(config_json, "net_device", &net_dev);

	if ((addr_v4 == NULL) ||
		(ret     != 0) ) {
		log_error("Invalid Config\n");
		goto err;
	}

	state = petnet_init(addr_v4, addr_v6, net_dev);

	/* Post Config Options */
	pet_json_get_bool(config_json, "debugging", &(state->debug_enable));



	pet_json_free(config_json);
	pet_free(config_data);

	return state;

err:
	if (config_data) pet_free(config_data);
	if (addr_v4)     free_ipv4_addr(addr_v4);

	if (config_json != PET_JSON_INVALID_OBJ) {
		pet_json_free(config_json);
	}

	return NULL;

}


int
petnet_run()
{
	petnet_state->driver->listen(petnet_state);

	return 0;

}

int
petnet_stop()
{
	return -1;
}