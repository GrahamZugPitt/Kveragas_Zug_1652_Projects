/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __SYS_H__
#define __SYS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "mac_address.h"

struct mac_addr * sys_get_iface_mac_addr(char * iface_name);

uint32_t sys_get_iface_mtu(char * iface_name);


#ifdef __cplusplus
}
#endif

#endif