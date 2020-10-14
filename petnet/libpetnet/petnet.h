/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#ifndef __PETNET_H__
#define __PETNET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <util/ip_address.h>
#include <util/mac_address.h>
#include <pthread.h>

struct petnet_timer_state;
struct petnet_driver_ops;
struct petnet_pkt_pool;
struct arp_state;
struct tcp_state;
struct socket_state;

struct petnet {
	struct ipv4_addr * addr_v4;
	struct ipv6_addr * addr_v6;
	struct mac_addr  * mac_addr;
	char             * net_dev;

	uint32_t device_mtu;
	uint32_t pkt_pool_size;

	struct petnet_driver      * driver;
	struct petnet_pkt_pool    * pkt_pool;
	struct petnet_timer_state * timers;

	struct arp_state    * arp_state;
	struct tcp_state    * tcp_state;
	struct udp_state    * udp_state;
	struct socket_state * socket_state;

	int debug_enable;

};

/* Access to the global petnet state is done through this variable */
extern struct petnet * petnet_state;


struct petnet *
petnet_init(struct ipv4_addr * addr_v4,
			struct ipv6_addr * addr_v6,
			char *			   net_dev);

struct petnet *
petnet_init_from_config(char * config_filename);


int
petnet_run();

int
petnet_stop();


#ifdef __cplusplus
}
#endif

#endif