/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __MAC_ADDRESS_H__
#define __MAC_ADDRESS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <petlib/pet_json.h>

struct mac_addr {
    uint8_t addr[6];
};

struct mac_addr * mac_addr_from_bytes(uint8_t * bytes);
struct mac_addr * mac_addr_from_octets(uint8_t * octets);
struct mac_addr * mac_addr_from_str(char * str);
struct mac_addr * mac_addr_from_json(pet_json_obj_t json, char * key);

struct mac_addr * mac_addr_clone(struct mac_addr * addr);
struct mac_addr * mac_broadcast_addr();


char * mac_addr_to_str(struct mac_addr * addr);

int mac_addr_to_json(struct mac_addr * addr, 
                     pet_json_obj_t    json, 
                     char            * key);


                    
int mac_addr_to_bytes(struct mac_addr * addr, 
                      uint8_t         * bytes);

int mac_addr_to_octets(struct mac_addr * addr, 
                       uint8_t         * octets);

int mac_addr_compare(struct mac_addr * addr1,
                     struct mac_addr * addr2);
                    
void free_mac_addr(struct mac_addr * addr);


int mac_addr_is_broadcast(struct mac_addr * addr);

#ifdef __cplusplus
}
#endif

#endif