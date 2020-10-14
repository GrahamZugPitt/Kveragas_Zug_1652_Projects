/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#ifndef __IPV4_H__
#define __IPV4_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define IPV4_PROTO_ICMP 0x01
#define IPV4_PROTO_TCP  0x06
#define IPV4_PROTO_UDP  0x11

struct packet;


/* Yes, some fields here are in reverse order due to network byte ordering */
struct ipv4_raw_hdr {
    uint8_t  header_len  : 4;
    uint8_t  version     : 4;
    uint8_t  ecn         : 2;
    uint8_t  dscp        : 6;
    uint16_t total_len;
    uint16_t frag_id;
    uint16_t frag_offset : 13;
    uint16_t flags       : 3;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];

    uint32_t options[0];
} __attribute__((packed));

/* Note: this is only used for checksum calculations in the transport layer */
struct ipv4_pseudo_hdr {
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
    uint8_t  rsvd;
    uint8_t  proto; 
    uint16_t length;
} __attribute__((packed));

pet_json_obj_t ipv4_hdr_to_json(struct ipv4_raw_hdr * hdr);
void           print_ipv4_header(struct ipv4_raw_hdr * ipv4_hdr);


/*
 * Returns the IPV4 header length that will be used for new pakcets
 */
int ipv4_expected_hdr_len();


int ipv4_pkt_rx(struct packet * pkt);

int ipv4_pkt_tx(struct packet    * pkt, 
                struct ipv4_addr * dst_addr);

#ifdef __cplusplus
}
#endif

#endif