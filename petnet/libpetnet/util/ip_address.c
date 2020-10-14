/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdlib.h>
#include <string.h>

#include "ip_address.h"

#include <petlib/pet_util.h>


static struct ipv4_addr * 
__create_ipv4_addr()
{
	struct ipv4_addr * addr = NULL;

	addr = pet_malloc(sizeof(struct ipv4_addr));

	return addr;
}

struct ipv4_addr *
ipv4_broadcast_addr()
{
	uint8_t bcast_bytes[4] = {0xff, 0xff, 0xff, 0xff};
	return ipv4_addr_from_bytes(bcast_bytes);
}

struct ipv4_addr *
ipv4_addr_from_bytes(uint8_t * bytes)
{
	struct ipv4_addr * addr = NULL;

	addr = __create_ipv4_addr();

	if (addr == NULL) {
		log_error("Could not create IPV4 Address\n");
		goto err;
	}

	memcpy(addr->addr, bytes, 4);

	return addr;

err:
	return NULL;
}

struct ipv4_addr *
ipv4_addr_from_octets(uint8_t * bytes)
{
	struct ipv4_addr * addr = NULL;

	addr = __create_ipv4_addr();

	if (addr == NULL) {
		log_error("Could not create IPV4 Address\n");
		goto err;
	}

	addr->addr[0] = bytes[3];
	addr->addr[1] = bytes[2];
	addr->addr[2] = bytes[1];
	addr->addr[3] = bytes[0];

	return addr;

err:
	return NULL;
}




struct ipv4_addr *
ipv4_addr_from_str(char * str)
{
	char             * str2    = strndup(str, strlen("xxx.xxx.xxx.xxx"));
	char             * tmp_str = str2;

	uint8_t raw_addr[4] = {0, 0, 0, 0};

	int ret = 0;
	int i = 0;

	for (i = 0; i < 3; i++) {
		char * end_ptr = index(tmp_str, '.');

		if (end_ptr == NULL) {
			log_error("Invalid IPV4 address\n");
			goto err;
		}


		*end_ptr = '\0';

		ret = pet_strtou8(tmp_str, &raw_addr[3 - i]);

		if (ret != 0) {
			log_error("Invalid IPV4 address byte (%d)\n", 4 - i);
			goto err;
		}

		tmp_str = end_ptr + 1;
	}

	ret = pet_strtou8(tmp_str, &raw_addr[0]);

	if (ret != 0) {
		log_error("Invalid IPV4 address byte (0)\n");
		goto err;
	}

	pet_free(str2);

	return ipv4_addr_from_bytes(raw_addr);

err:
	if (str2) pet_free(str2);

	return NULL;
}


struct ipv4_addr *
ipv4_addr_from_json(pet_json_obj_t   json, 
					char           * key)
{
	char * addr_str = NULL;
	int ret = 0;

	ret = pet_json_get_string(json, key, &addr_str);

	if (ret != 0) {
		log_error("Could not find JSON field (%s)\n", key);
		goto err;
	}

	return ipv4_addr_from_str(addr_str);
err:
	return NULL;
}

char *
ipv4_addr_to_str(struct ipv4_addr * addr)
{
	char * addr_str = NULL;

	int ret = 0;

	ret = pet_asprintf(&addr_str, "%d.%d.%d.%d", addr->addr[3], addr->addr[2], addr->addr[1], addr->addr[0]);

	if (ret == -1) {
		log_error("Could not serialize IPV4 address\n");
		goto err;
	}

	return addr_str;

err:
	if (addr_str) pet_free(addr_str);

	return NULL;
}

int 
ipv4_addr_to_json(struct ipv4_addr * addr,
				  pet_json_obj_t     json, 
				  char             * key)
{
	return pet_json_add_string(json, key, ipv4_addr_to_str(addr));
}


int
ipv4_addr_to_bytes(struct ipv4_addr * addr,
				   uint8_t          * bytes)
{
	memcpy(bytes, addr->addr, 4);
	return 0;
}

int
ipv4_addr_to_octets(struct ipv4_addr * addr,
				    uint8_t          * octets)
{
	octets[0] = addr->addr[3];
	octets[1] = addr->addr[2];
	octets[2] = addr->addr[1];
	octets[3] = addr->addr[0];

	return 0;
}

struct ipv4_addr *
ipv4_addr_clone(struct ipv4_addr * addr)
{
	return ipv4_addr_from_bytes(addr->addr);
}

int
ipv4_addr_compare(struct ipv4_addr * addr1,
				  struct ipv4_addr * addr2)
{
	return memcmp(addr1->addr, addr2->addr, 4);
}

void
free_ipv4_addr(struct ipv4_addr * addr)
{
	pet_free(addr);
}

int 
ipv4_addr_is_nil(struct ipv4_addr * addr)
{
	uint8_t nil_addr[4] = {0, 0, 0, 0};

	return (memcmp(addr->addr, nil_addr, 4) == 0);
}