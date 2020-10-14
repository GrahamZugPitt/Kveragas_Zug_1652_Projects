/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __IP_ADDRESS_H__
#define __IP_ADDRESS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <petlib/pet_json.h>

typedef enum { IPV4_NETWORK, IPV6_NETWORK } ip_net_type_t;
typedef enum { IPV4_ADDR, IPV6_ADDR } ip_addr_type_t;

struct ipv4_addr {
	uint8_t addr[4];
};

struct ipv6_addr {
	uint8_t addr[16];
};

struct ip_addr {
	ip_addr_type_t type;

	union {
		struct ipv4_addr addr_v4;
		struct ipv6_addr addr_v6;
	};
};


/* 
 * IP Address creation functions 
 * 
 * Creates an IP Address from multiple representations
 * bytes   : raw 32 bit value (host byte order)
 * octects : raw 32 bit value (network byte order)
 * str     : ASCII dotted quad notation
 * json    : ASCII dotted quad notation embedded in JSON object
 */ 
struct ipv4_addr * ipv4_addr_from_bytes(uint8_t * bytes);
struct ipv4_addr * ipv4_addr_from_octets(uint8_t * octets);
struct ipv4_addr * ipv4_addr_from_str(char * str);
struct ipv4_addr * ipv4_addr_from_json(pet_json_obj_t json, char * key);

/* 
 * Creates a broadcast (255.255.255.255) ip address
 */
struct ipv4_addr * ipv4_broadcast_addr();

/* 
 * Clone an ip address
 */
struct ipv4_addr * ipv4_addr_clone(struct ipv4_addr * addr);

/*
 * Serialization functions
 * 
 * Destination types are same as creation functions
 */ 
char * ipv4_addr_to_str(struct ipv4_addr * addr);

int ipv4_addr_to_json(struct ipv4_addr * addr,
					  pet_json_obj_t     json, 
					  char             * key);

int ipv4_addr_to_bytes(struct ipv4_addr * addr, 
					   uint8_t          * dst);

int ipv4_addr_to_octets(struct ipv4_addr * addr, 
					    uint8_t          * dst);



/* 
 * Check if the IP Address is nil (0.0.0.0)
 */
int ipv4_addr_is_nil(struct ipv4_addr * addr);

/*
 * Compare two ip addresses
 * 
 * Returns a comparison result:
 * 	-1 if addr1 is less than addr2
 *   0 if addr1 is equal to addr2
 *   1 if addr1 is greater than addr2
 */
int ipv4_addr_compare(struct ipv4_addr * addr1,
					  struct ipv4_addr * addr2);

/*
 * Free's ipv4_addr
 * 
 * IMPORTANT: You must use this function to free an ip address
 */ 
void free_ipv4_addr(struct ipv4_addr * addr);


#ifdef __cplusplus
}
#endif

#endif