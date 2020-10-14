/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __PORT_MAP_H__
#define __PORT_MAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


struct port_map;


struct port_map * port_map_create();

void port_map_free(struct port_map * map);

/* 
 * Allocates given port number for a socket
 * -  if (port == 0) then a random port number will be generated for you
 * 
 * Returns 0 on failure, otherwise returns port number allocated 
 */
uint16_t port_map_alloc(struct port_map * map, uint16_t port);


/* 
 * Releases a given port number for use by another socket
 */
void port_map_release(struct port_map * map, uint16_t port);


#ifdef __cplusplus
}
#endif

#endif