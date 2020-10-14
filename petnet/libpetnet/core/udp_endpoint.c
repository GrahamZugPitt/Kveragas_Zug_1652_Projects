/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <pthread.h>

#include <petnet.h>

#include <util/ip_address.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>

#include "udp_endpoint.h"
#include "socket.h"


struct udp_endpoint_map {
    struct pet_hashtable * ipv4_table;
    struct pet_hashtable * ipv6_table;
    struct pet_hashtable * sock_table;

    pthread_mutex_t lock;
};


static uint32_t 
__ipv4_tuple_hash_fn(uintptr_t key)
{
    struct udp_ipv4_tuple * tuple = (struct udp_ipv4_tuple *)key;
    uint8_t tmp_buf[6];

    ipv4_addr_to_bytes(tuple->local_ip,  tmp_buf);
    *(uint16_t *)(tmp_buf + 4 ) = tuple->local_port;

    return pet_hash_buffer(tmp_buf, 6);
}


static int
__ipv4_tuple_eq_fn(uintptr_t key1, 
                   uintptr_t key2)
{
    struct udp_ipv4_tuple * tuple_1 = (struct udp_ipv4_tuple *)key1;
    struct udp_ipv4_tuple * tuple_2 = (struct udp_ipv4_tuple *)key2;

    if ((ipv4_addr_compare(tuple_1->local_ip,  tuple_2->local_ip)  == 0) &&
        (tuple_1->local_port == tuple_2->local_port)) {
        return 1;
    }

    return 0;
}


static void
__free_udp_endpoint(struct udp_endpoint * endpoint)
{
    if (endpoint) {

        // log_debug("FREEING UDP endpoint (%p)\n", endpoint);

        if (endpoint->net_type == IPV4_NETWORK) {
            if (endpoint->ipv4_tuple.local_ip) free_ipv4_addr(endpoint->ipv4_tuple.local_ip);
        }

        if (endpoint->sock) pet_put_socket(endpoint->sock);

        pet_free(endpoint);
    }
}

struct udp_endpoint *
get_udp_endpoint(struct udp_endpoint * endpoint)
{
    pet_atomic_inc(&(endpoint->ref_cnt));
    return endpoint;
}

void
put_udp_endpoint(struct udp_endpoint * endpoint)
{
    int ref_cnt = 0;

    ref_cnt = pet_atomic_dec(&(endpoint->ref_cnt));

    if (ref_cnt == 0) {
        __free_udp_endpoint(endpoint);
    }
}


void
unlock_udp_endpoint(struct udp_endpoint * endpoint)
{
    pthread_mutex_unlock(&(endpoint->lock));
}

void
lock_udp_endpoint(struct udp_endpoint * endpoint)
{
    pthread_mutex_lock(&(endpoint->lock));
}


void
put_and_unlock_udp_endpoint(struct udp_endpoint * endpoint)
{
    pthread_mutex_unlock(&(endpoint->lock));
    put_udp_endpoint(endpoint);
}

struct udp_endpoint *
get_and_lock_udp_endpoint_from_ipv4(struct udp_endpoint_map * map,
                                    struct ipv4_addr        * local_ip,
                                    uint16_t                  local_port)
{
    struct udp_ipv4_tuple ipv4_tuple;

    struct udp_endpoint * endpoint = NULL;
    
    memset(&ipv4_tuple, 0, sizeof(struct udp_ipv4_tuple));

    ipv4_tuple.local_ip   = local_ip;
    ipv4_tuple.local_port = local_port;

    pthread_mutex_lock(&(map->lock));
    {
        endpoint = pet_htable_search(map->ipv4_table, (uintptr_t)&ipv4_tuple);

        if (endpoint) {
            pet_atomic_inc(&(endpoint->ref_cnt));            
        }
    }
    pthread_mutex_unlock(&(map->lock));

    if (endpoint) {
        pthread_mutex_lock(&(endpoint->lock));
    }

    return endpoint;
}

struct udp_endpoint *
get_and_lock_udp_endpoint_from_sock(struct udp_endpoint_map * map,
                                    struct socket           * sock)
{
    struct udp_endpoint * endpoint = NULL;

    pthread_mutex_lock(&(map->lock));
    {
        endpoint = pet_htable_search(map->sock_table, (uintptr_t)sock);
    
        if (endpoint) {
            pet_atomic_inc(&(endpoint->ref_cnt));
        }
    }
    pthread_mutex_unlock(&(map->lock));

    if (endpoint) {
        pthread_mutex_lock(&(endpoint->lock));
    }

    return endpoint;
}

struct udp_endpoint *
create_ipv4_udp_endpoint(struct udp_endpoint_map * map,
                         struct socket           * sock,
                         struct ipv4_addr        * local_ip,
                         uint16_t                  local_port)
{
    struct udp_endpoint * endpoint = NULL;

    int ret = 0;

    endpoint = pet_malloc(sizeof(struct udp_endpoint));

    endpoint->net_type              = IPV4_NETWORK;
    endpoint->ipv4_tuple.local_ip   = ipv4_addr_clone(local_ip);
    endpoint->ipv4_tuple.local_port = local_port;
    endpoint->sock                  = pet_get_socket(sock);
    endpoint->ref_cnt               = 1;

    pthread_mutex_init(&(endpoint->lock), NULL);

    pthread_mutex_lock(&(map->lock));
    {
        ret |= pet_htable_insert(map->ipv4_table, (uintptr_t)&(endpoint->ipv4_tuple), (uintptr_t)endpoint);
        ret |= pet_htable_insert(map->sock_table, (uintptr_t)(endpoint->sock),        (uintptr_t)endpoint);
    }
    pthread_mutex_unlock(&(map->lock));

    if (ret != 0) {
        log_error("Could not create new UDP endpoint\n");
        goto err;
    }

    get_udp_endpoint(endpoint);
    pthread_mutex_lock(&(endpoint->lock));

    return endpoint;
err:
    if (endpoint) __free_udp_endpoint(endpoint);

    return NULL;
}



void
remove_udp_endpoint(struct udp_endpoint_map * map,
                    struct udp_endpoint     * endpoint)
{
    pthread_mutex_lock(&(map->lock));
    {
        if (endpoint->net_type == IPV4_NETWORK) {
            pet_htable_remove(map->ipv4_table, (uintptr_t)&(endpoint->ipv4_tuple));
        } else if (endpoint->net_type == IPV6_NETWORK) {
            // remove from ipv6_table
        }

        pet_htable_remove(map->sock_table, (uintptr_t)endpoint->sock);
    }
    pthread_mutex_unlock(&(map->lock));

    put_udp_endpoint(endpoint);

    return;
}


void
free_udp_endpoint_map(struct udp_endpoint_map * map)
{
    if (map->ipv4_table) {
        if (pet_htable_count(map->ipv4_table) != 0) {
            log_error("Memory leak!! Freeing non-empty tcp connection table\n");
        }

        pet_free_htable(map->ipv4_table);
    }

    /*
    if (map->ipv6_table) {
        if (pet_htable_count(map->ipv6_table) != 0) {
            log_error("Memory leak!! Freeing non-empty tcp connection table\n");
        }

        pet_free_htable(map->ipv_table);
    }
    */

    if (map->sock_table) {
        if (pet_htable_count(map->sock_table) != 0) {
            log_error("Memory leak!! Freeing non-empty tcp connection table\n");
        }

        pet_free_htable(map->sock_table);
    }

    pet_free(map);  

}

struct udp_endpoint_map *
create_udp_endpoint_map()
{
    struct udp_endpoint_map * map = pet_malloc(sizeof(struct udp_endpoint_map));

    map->ipv4_table = pet_create_htable(0, __ipv4_tuple_hash_fn, __ipv4_tuple_eq_fn, NULL, NULL);
    //    con_map->ipv6_table = pet_create_htable(0, __ipv6_tuple_hash_fn, __ipv6_tuple_eq_fn, NULL, NULL);
    map->sock_table = pet_create_htable(0, pet_hash_ptr, pet_cmp_ptr, NULL, NULL);

    pthread_mutex_init(&(map->lock), NULL);

    return map;
}