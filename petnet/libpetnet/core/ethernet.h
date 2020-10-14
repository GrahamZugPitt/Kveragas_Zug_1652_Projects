/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <petnet.h>

#include "packet.h"


/* Ethertype  */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_ROCE 0x8915
#define ETHERTYPE_RARP 0x8035

struct eth_raw_hdr {
/*
    uint8_t preamble[7];
    uint8_t delimiter;
*/
    uint8_t dst_mac[6];
    uint8_t src_mac[6];

    uint16_t ether_type;
    
} __attribute__((packed));


int
ethernet_pkt_rx(struct packet * pkt);


int
ethernet_pkt_tx(struct packet   * pkt, 
                struct mac_addr * dst_mac);


void
print_ethernet_hdr(struct eth_raw_hdr * eth_hdr);

#ifdef __cplusplus
}
#endif

#endif