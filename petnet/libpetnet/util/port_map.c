/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <stdint.h>
#include <pthread.h>
#include <string.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>


#include "port_map.h"

struct port_map {
    uint8_t port_bitmap[8192];

    pthread_mutex_t lock;
};



static int
__get_bit(uint8_t  * bitmap, 
          uint16_t   index)
{
    uint16_t major_idx = index / 8;
    uint16_t minor_idx = index % 8;

   return ((bitmap[major_idx] & (0x1 << minor_idx)) != 0);
}


static void
__set_bit(uint8_t  * bitmap, 
          uint16_t   index)
{
    uint16_t major_idx = index / 8;
    uint16_t minor_idx = index % 8;

    bitmap[major_idx] |= (0x1 << minor_idx);
}

static void
__clr_bit(uint8_t  * bitmap, 
          uint16_t   index)
{
    uint16_t major_idx = index / 8;
    uint16_t minor_idx = index % 8;

    bitmap[major_idx] &= ~(0x1 << minor_idx);
}


static int
__port_is_allocated(struct port_map * map, 
                    uint16_t          port)
{
    return __get_bit(map->port_bitmap, port);
}


static uint16_t 
__find_free_port(struct port_map * map)
{
    uint16_t start_port = 0;
    uint16_t port       = 0;

    int success = 0;
    int ret     = 0;
    int i       = 0;

    ret = pet_get_rand_bytes((uint8_t *)&start_port, 2);

    if (ret != 0) {
        log_error("System Error: Could not get random port...");
        return 0;
    }

    for (i = 0; i < 65535; i++) {
        port = start_port + i; // On overflow we will wrap to zero

        if (port <= 1024) {
            // Skip the reserved ports
            continue;
        }

        if (__port_is_allocated(map, port) == 0) {
            success = 1;
            break;
        }
    }

    if (success == 0) {
        return 0;
    }

    return port;
}

static uint16_t 
__alloc_port(struct port_map * map, 
             uint16_t          port)
{
    if (port == 0) {
        port = __find_free_port(map);
    }

    if (port == 0) {
        /* No free ports available */
        log_error("Port Space Exhausted. No Available Ports\n");            
        return 0;
    }

    if (__port_is_allocated(map, port)) {
        log_error("Port is already in use\n");
        return 0;
    }

    /* Mark port as allocated */
    __set_bit(map->port_bitmap, port);

    return port;
}

uint16_t 
port_map_alloc(struct port_map * map, 
               uint16_t          port)
{
    uint16_t tmp_port = 0;

    pthread_mutex_lock(&(map->lock));
    {
        tmp_port = __alloc_port(map, port);
    }
    pthread_mutex_unlock(&(map->lock));


    return tmp_port;
}


void
port_map_release(struct port_map * map, 
                 uint16_t          port)
{

    if (port == 0) {
        log_error("Tried to release invalid port\n");
        return;
    }

    pthread_mutex_lock(&(map->lock));
    {
        __clr_bit(map->port_bitmap, port);
    }
    pthread_mutex_unlock(&(map->lock));

    return;
}



struct port_map * 
port_map_create()
{
    struct port_map * map = pet_malloc(sizeof(struct port_map));

    pthread_mutex_init(&(map->lock), NULL);
    memset(map->port_bitmap, 0, 8192);

    __set_bit(map->port_bitmap, 0); // Disallow port 0

    return map;
}


void
port_map_free(struct port_map * map)
{
    pet_free(map);
}