/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __TCP_H__
#define __TCP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct ipv4_addr;
struct socket;
struct packet;


/* Yes, some fields here are in reverse order due to network byte ordering */
struct tcp_raw_hdr {
    uint16_t src_port;
    uint16_t dst_port; 
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  rsvd       : 4;
    uint8_t  header_len : 4;


    struct {
        uint8_t FIN        : 1;
        uint8_t SYN        : 1;
        uint8_t RST        : 1;
        uint8_t PSH        : 1;
        uint8_t ACK        : 1;
        uint8_t URG        : 1;
        uint8_t rsvd2      : 2;
    } flags;

    uint16_t recv_win;
    uint16_t checksum;
    uint16_t urgent_ptr;
    uint8_t  options[0];
} __attribute__((packed));


/* Socket API Calls */

/* 
 * Application Called connect(())
 */
int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * src_addr,
                 uint16_t           src_port,
                 struct ipv4_addr * dst_addr,
                 uint16_t           dst_port);


/* 
 * Application Called listen()
 */
int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port);

/*
 * Application called send()
 */
int
tcp_send(struct socket * sock);


/* 
 * Application called close()
 */
int
tcp_close(struct socket * sock);

/* Upcalls */

/* 
 * TCP Packet was received from network
 */
int 
tcp_pkt_rx(struct packet * pkt);



int 
tcp_init(struct petnet * petnet_state);

#ifdef __cplusplus
}
#endif

#endif