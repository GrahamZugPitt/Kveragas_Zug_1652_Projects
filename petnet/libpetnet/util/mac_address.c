/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdlib.h>
#include <string.h>

#include "mac_address.h"

#include <petlib/pet_util.h>

static uint8_t broadcast_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static struct mac_addr *
__create_mac_addr() {
    struct mac_addr * addr = NULL;

    addr = pet_malloc(sizeof(struct mac_addr));

    return addr;
} 

struct mac_addr *
mac_addr_from_bytes(uint8_t * bytes)
{
    struct mac_addr * addr = NULL;

    addr = __create_mac_addr();

    if (addr == NULL) {
        log_error("Could not create MAC Address\n");
        goto err;
    }

    memcpy(addr->addr, bytes, 6);

    return addr;
err:
    return NULL;
}


struct mac_addr *
mac_addr_from_octets(uint8_t * octets)
{
    struct mac_addr * addr = NULL;

    addr = __create_mac_addr();

    if (addr == NULL) {
        log_error("Could not create MAC Address\n");
        goto err;
    }

    addr->addr[0] = octets[5];
    addr->addr[1] = octets[4];
    addr->addr[2] = octets[3];
    addr->addr[3] = octets[2];
    addr->addr[4] = octets[1];
    addr->addr[5] = octets[0];


    return addr;
err:
    return NULL;
}

struct mac_addr *
mac_addr_from_str(char * str)
{
  	char             * str2    = strndup(str, strlen("xx:xx:xx:xx:xx:xx"));
	char             * tmp_str = str2;

	uint8_t raw_addr[6] = {0, 0, 0, 0, 0, 0};

	int ret = 0;
	int i = 0;

	for (i = 0; i < 5; i++) {
		char * end_ptr = index(tmp_str, ':');

		if (end_ptr == NULL) {
			log_error("Invalid MAC address\n");
			goto err;
		}


		*end_ptr = '\0';

		ret = pet_strtou8_hex(tmp_str, &raw_addr[5 - i]);

		if (ret != 0) {
			log_error("Invalid MAC address byte (%d)\n", 6 - i);
			goto err;
		}

		tmp_str = end_ptr + 1;
	}

	ret = pet_strtou8_hex(tmp_str, &raw_addr[0]);

	if (ret != 0) {
		log_error("Invalid MAC address byte (0)\n");
		goto err;
	}

	pet_free(str2);

	return mac_addr_from_bytes(raw_addr);

err:
	if (str2) pet_free(str2);

	return NULL;  

}

struct mac_addr *
mac_addr_from_json(pet_json_obj_t   json, 
                   char           * key)
{
    char * addr_str = NULL;
    int    ret      = 0;

    ret = pet_json_get_string(json, key, &addr_str);

    if (ret != 0) {
        log_error("Could not find JSON field (%s)\n", key);
        goto err;
    }

    log_debug("mac_addr_str=%s\n", addr_str);

    return mac_addr_from_str(addr_str);

err:
    return NULL;
}

char *
mac_addr_to_str(struct mac_addr * addr)
{
    char * addr_str = NULL;

    int ret = 0;

    ret = pet_asprintf(&addr_str, 
                       "%x:%x:%x:%x:%x:%x", 
                       addr->addr[5], 
                       addr->addr[4], 
                       addr->addr[3], 
                       addr->addr[2], 
                       addr->addr[1], 
                       addr->addr[0]);

    if (ret == -1) {
        log_error("Could not serialize MAC address\n");
        goto err;
    }

    return addr_str;

err:
    if (addr_str) pet_free(addr_str);

    return NULL;
}


int
mac_addr_to_json(struct mac_addr * addr,
                 pet_json_obj_t    json,
                 char            * key)
{
    return pet_json_add_string(json, key, mac_addr_to_str(addr));
}

int 
mac_addr_to_bytes(struct mac_addr * addr, 
                  uint8_t         * bytes)
{
    memcpy(bytes, addr->addr, 6);
    return 0;
}

int 
mac_addr_to_octets(struct mac_addr * addr, 
                   uint8_t         * octets)
{
    octets[0] = addr->addr[5];
    octets[1] = addr->addr[4];
    octets[2] = addr->addr[3];
    octets[3] = addr->addr[2];
    octets[4] = addr->addr[1];
    octets[5] = addr->addr[0];

    return 0;
}


struct mac_addr *
mac_addr_clone(struct mac_addr * addr)
{
    return mac_addr_from_bytes(addr->addr);
}

struct mac_addr * 
mac_broadcast_addr()
{
    return mac_addr_from_bytes(broadcast_addr);
}

int
mac_addr_compare(struct mac_addr * addr1, 
                 struct mac_addr * addr2)
{
    return memcmp(addr1->addr, addr2->addr, 6);
}

int
mac_addr_is_broadcast(struct mac_addr * addr)
{
    return (memcmp(addr->addr, broadcast_addr, 6) == 0);
}

void
free_mac_addr(struct mac_addr * addr)
{
    pet_free(addr);
}
