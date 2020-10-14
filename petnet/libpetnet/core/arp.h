/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#ifndef __ARP_H__
#define __ARP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct packet;
struct ipv4_addr;

struct arp_raw_hdr {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t  hw_addr_len;
	uint8_t  proto_addr_len;
	uint16_t opcode;

	uint8_t  src_mac[6];
	uint8_t  src_ip[4];

	uint8_t  tgt_mac[6];
	uint8_t  tgt_ip[4];
} __attribute__((packed));

int 
arp_pkt_rx(struct packet * pkt);


int
arp_lookup_and_tx(struct packet    * pkt, 
				  struct ipv4_addr * dst_addr);

int 
arp_init(struct petnet * petnet_state);

#ifdef __cplusplus
}
#endif

#endif