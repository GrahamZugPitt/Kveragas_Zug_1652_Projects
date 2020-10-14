/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __UDP_H__
#define __UDP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>

struct petnet_state;
struct packet;
struct socket;

struct udp_raw_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));


int 
udp_bind(struct socket    * sock, 
         struct ipv4_addr * local_addr,
         uint16_t           local_port);


int
udp_close(struct socket * sock);

int udp_pkt_rx(struct packet * pkt);





int udp_send_datagram(struct socket    * sock,
                      void             * buf,
                      size_t             len,
                      struct ipv4_addr * remote_addr,
                      uint16_t           remote_port);


int udp_init(struct petnet * petnet_state);

#ifdef __cplusplus
}
#endif

#endif