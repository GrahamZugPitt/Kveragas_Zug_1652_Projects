/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#ifndef __PACKET_H__
#define __PACKET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <petlib/pet_list.h>

typedef enum {ETHERNET_PKT} layer_2_type_t;

typedef enum {IPV4_PKT, 
              IPV6_PKT, 
              ARP_PKT} layer_3_type_t;

typedef enum {TCP_PKT, 
              UDP_PKT, 
              ICMP_PKT} layer_4_type_t;


/* 
 * Packet Data Structure
 * 
 * A struct packet is a flexible data type that allows multiple ways of referencing packet data
 * It is used differently depending on whether the packet is incoming or outgoing.
 * The implementation allows working with either a contiguous or sparse data layout with the same API.
 * Freeing a packet deallocates all of the memory blocks associated with it, regardless of whether 
 * they are sparse or contiguous.
 * 
 * Incoming (received) packets are stored as a single contiguous memory region with the
 *      packet structure at offset 0, and packet data starting at the offset of ->buf
 *      Packet header pointers are then set to point to offsets inside the buffer contents 
 *      as the packet moves up the protocol stack.
 * 
 * Outgoing packets are stored with a sparse layout where each header and the packet data are 
 *      stored in separately allocated memory blocks. Each header is dynamically allocated as the 
 *      packet moves down the protocol stack until being coalesced as it is transmitted.
 */

struct packet {

    struct list_head list_node;

    int ref_cnt;

    layer_2_type_t   layer_2_type;
    uint32_t         layer_2_hdr_len;
    void           * layer_2_hdr;
    layer_3_type_t   layer_3_type;
    uint32_t         layer_3_hdr_len;
    void           * layer_3_hdr;
    layer_4_type_t   layer_4_type;
    uint32_t         layer_4_hdr_len;
    void           * layer_4_hdr;

    uint32_t         payload_len;
    void           * payload;


    uint32_t buf_len;  // amount of actual data stored in buf[]
    uint32_t buf_size; // amount of memory allocated for buf[] 

    uint8_t buf[0];
};


/* 
 * Create a bare packet structure
 * Headers and payload can be added dynamically via pointer assignment
 * 
 * Use this to create sparse packets
 */
struct packet * create_empty_packet();

/* 
 * Create a packet with a preallocated data buffer
 *  
 * Use these to create contiguous packets
 */
struct packet * create_packet(uint32_t pkt_size);
struct packet * create_raw_packet(uint8_t * raw_data, uint32_t raw_data_len);


/*
 * Frees a packet structure and any associated memory blocks
 */
void free_packet(struct packet * pkt);



/* 
 * Reinitiallizes a contiguous packet to make it available for re-use
 */
void release_packet(struct packet * pkt);


#ifdef __cplusplus
}
#endif

#endif