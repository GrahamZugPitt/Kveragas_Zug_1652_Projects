/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#ifndef __ICMP_H__
#define __ICMP_H__

#ifdef __cplusplus
extern "C" {
#endif



#include <stdint.h>


struct packet;

struct icmp_raw_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    union {
        uint32_t aux_hdr;

        struct {
            uint16_t id;
            uint16_t seq_num;
        } icmp_echo_hdr;

    } __attribute__((packed));
} __attribute__((packed));


int
icmp_pkt_rx(struct packet * pkt);


#ifdef __cplusplus
}
#endif

#endif