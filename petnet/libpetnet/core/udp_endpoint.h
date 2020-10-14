/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __UDP_ENDPOINT_H__
#define __UDP_ENDPOINT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <pthread.h>

struct udp_endpoint_map;
struct ipv4_addr;
struct socket;

struct udp_ipv4_tuple {
    struct ipv4_addr * local_ip;
    uint16_t           local_port;
};

struct udp_endpoint {

    ip_net_type_t net_type;

    union {
        struct udp_ipv4_tuple ipv4_tuple;
    };
    
    int ref_cnt;

    pthread_mutex_t lock;

    struct socket * sock;

};


struct udp_endpoint * 
get_and_lock_udp_endpoint_from_sock(struct udp_endpoint_map * map,
                                    struct socket           * socket);

struct udp_endpoint *
get_and_lock_udp_endpoint_from_ipv4(struct udp_endpoint_map * map,
                                    struct ipv4_addr        * local_ip,
                                    uint16_t                  local_port);


void 
put_and_unlock_udp_endpoint(struct udp_endpoint * endpoint);



void
put_udp_endpoint(struct udp_endpoint * endpoint);

struct udp_endpoint *
get_udp_endpoint(struct udp_endpoint * endpoint);

void
unlock_udp_endpoint(struct udp_endpoint * endpoint);

void
lock_udp_endpoint(struct udp_endpoint * endpoint);




struct udp_endpoint *
create_ipv4_udp_endpoint(struct udp_endpoint_map * map,
                         struct socket           * sock,
                         struct ipv4_addr        * local_ip,
                         uint16_t                  local_port);


void
remove_udp_endpoint(struct udp_endpoint_map * map,
                    struct udp_endpoint     * endpoint);


struct udp_endpoint_map * create_udp_endpoint_map();

#ifdef __cplusplus
}
#endif

#endif