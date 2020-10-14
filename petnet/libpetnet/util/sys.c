/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include <petlib/pet_log.h>
#include <petlib/pet_file.h>
#include <petlib/pet_util.h>

#include "mac_address.h"

#define SYSFS_NET_DIR "/sys/class/net/"


/* 
 * sysfs screws up the file size reporting, so we have to specialize the file read functions 
 */
static int
__sysfs_read_file(const char  * path,
                  uint8_t    ** buf,
                  size_t      * size)
{
	FILE        * file_ptr = NULL;
	struct stat   file_stats;
    
	size_t        file_size  = 0;
	uint8_t     * file_data = NULL;
    
	int ret = 0;
    
	ret = stat(path, &file_stats);

	if (ret == -1) {
		log_error("Could not stat file (%s)\n", path);
		return -1;
	}

	file_size = file_stats.st_size;

	if (file_size <= 0) {
		*size = 0;
		*buf = (uint8_t *)pet_malloc(1);

		return 0;
	}

	// We add an extra byte here to make sure strings are NULL terminated
	file_data = (uint8_t *)pet_malloc(file_size + 1); 

	file_ptr  = fopen(path, "rb");

	if (file_ptr == NULL) {
		log_error("Could not open file (%s)\n", path);
		goto out;
	}

	ret = fread(file_data, 1, file_size, file_ptr);

	if (ret == 0) {
		pet_free(file_data);
		goto out;
	}

	*buf  = file_data;
	*size = file_size;
    
 out:
	fclose(file_ptr);
    
	return ret;
}



struct mac_addr * 
sys_get_iface_mac_addr(char * iface_name)
{
    struct mac_addr * addr           = NULL;
    char            * addr_str       = NULL;
    char            * addr_file_name = NULL;

    size_t addr_len = 0;
    int ret = 0;

    ret = pet_asprintf(&addr_file_name, SYSFS_NET_DIR "%s/address", iface_name);

    if (ret == -1) {
        log_error("Could not allocate address filename\n");
        goto err;
    }

    ret = __sysfs_read_file(addr_file_name, (uint8_t **)&addr_str, &addr_len);

    if (ret == -1) {
        log_error("Could not read address sysfs file (%s)\n", addr_file_name);
        goto err;
    }

    addr = mac_addr_from_str(addr_str);

    if (addr == NULL) {
        log_error("Invalid MAC address string from sysfs\n");
        goto err;
    }

    pet_free(addr_str);
    pet_free(addr_file_name);

    return addr;

err:

    if (addr_file_name) pet_free(addr_file_name);
    if (addr_str)       pet_free(addr_str);
    if (addr)           free_mac_addr(addr);

    return NULL;

}



uint32_t
sys_get_iface_mtu(char * iface_name)
{
    char   * file_name = NULL;
    char   * mtu_str       = NULL;

    size_t   file_len = 0;  
    uint32_t mtu      = 0;

    int ret = 0;

    ret = pet_asprintf(&file_name, SYSFS_NET_DIR "%s/mtu", iface_name);

    if (ret == -1) {
        log_error("Could not allocate address filename\n");
        goto err;
    }

    ret = __sysfs_read_file(file_name, (uint8_t **)&mtu_str, &file_len);

    if (ret == -1) {
        log_error("Could not read address sysfs file (%s)\n", file_name);
        goto err;
    }

    ret = pet_strtou32(mtu_str, &mtu);

    if (ret == -1) {
        log_error("Invalid MAC address string from sysfs\n");
        goto err;
    }

    pet_free(mtu_str);
    pet_free(file_name);

    return mtu;

err:

    if (file_name) pet_free(file_name);
    if (mtu_str)   pet_free(mtu_str);

    return 0;

}