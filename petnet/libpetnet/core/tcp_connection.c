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

#include "tcp_connection.h"
#include "socket.h"



struct tcp_con_map {
    struct pet_hashtable * ipv4_table;
    struct pet_hashtable * ipv6_table;
    struct pet_hashtable * sock_table;

    pthread_mutex_t lock;
};

static uint32_t 
__ipv4_tuple_hash_fn(uintptr_t key)
{
    struct tcp_con_ipv4_tuple * tuple = (struct tcp_con_ipv4_tuple *)key;
    uint8_t tmp_buf[12];

    ipv4_addr_to_bytes(tuple->local_ip,  tmp_buf);
    ipv4_addr_to_bytes(tuple->remote_ip, tmp_buf + 4);
    *(uint16_t *)(tmp_buf + 8 ) = tuple->local_port;
    *(uint16_t *)(tmp_buf + 10) = tuple->remote_port;

    return pet_hash_buffer(tmp_buf, 12);
}


static int
__ipv4_tuple_eq_fn(uintptr_t key1, 
                   uintptr_t key2)
{
    struct tcp_con_ipv4_tuple * tuple_1 = (struct tcp_con_ipv4_tuple *)key1;
    struct tcp_con_ipv4_tuple * tuple_2 = (struct tcp_con_ipv4_tuple *)key2;


    if ((ipv4_addr_compare(tuple_1->local_ip,  tuple_2->local_ip)  == 0) &&
        (ipv4_addr_compare(tuple_1->remote_ip, tuple_2->remote_ip) == 0) &&
        (tuple_1->remote_port == tuple_2->remote_port)                   &&
        (tuple_1->local_port == tuple_2->local_port)) {
        return 1;
    }

    return 0;
}



static void
__free_tcp_connection(struct tcp_connection * con)
{
    if (con) {
        // log_debug("FREEING TCP CONNECTION (sock=%p)\n", con->sock);

        if (con->ipv4_tuple.local_ip)  free_ipv4_addr(con->ipv4_tuple.local_ip);
        if (con->ipv4_tuple.remote_ip) free_ipv4_addr(con->ipv4_tuple.remote_ip);
        if (con->sock)                 pet_put_socket(con->sock);

        pet_free(con);
    }
}



int 
lock_tcp_con(struct tcp_connection * con)
{
    return pthread_mutex_lock(&(con->con_lock));
}


int 
unlock_tcp_con(struct tcp_connection * con)
{
    return pthread_mutex_unlock(&(con->con_lock));
}


struct tcp_connection *
get_tcp_con(struct tcp_connection * con)
{
    int ref_cnt = 0;
    
    ref_cnt = pet_atomic_inc(&(con->ref_cnt));

    (void)ref_cnt;
    // log_debug("Getting TCP CON (ref_cnt = %d)\n", ref_cnt);

    return con;
}

void
put_tcp_con(struct tcp_connection * con)
{
    int ref_cnt = 0;

    ref_cnt = pet_atomic_dec(&(con->ref_cnt));

    //log_debug("PUTTING TCP CON (ref_cnt = %d)\n", ref_cnt);


    if (ref_cnt == 0) {
        __free_tcp_connection(con);
    }
}

void 
put_and_unlock_tcp_con(struct tcp_connection * con)
{
    pthread_mutex_unlock(&(con->con_lock));
    put_tcp_con(con);
}



struct tcp_connection *
get_and_lock_tcp_con_from_ipv4(struct tcp_con_map * map,
                               struct ipv4_addr   * local_ip, 
                               struct ipv4_addr   * remote_ip,
                               uint16_t             local_port,
                               uint16_t             remote_port)
{
    struct tcp_con_ipv4_tuple ipv4_tuple;

    struct tcp_connection * con = NULL;

    memset(&ipv4_tuple, 0, sizeof(struct tcp_con_ipv4_tuple));

    ipv4_tuple.local_ip    = local_ip;
    ipv4_tuple.remote_ip   = remote_ip;
    ipv4_tuple.local_port  = local_port;
    ipv4_tuple.remote_port = remote_port;


    pthread_mutex_lock(&(map->lock));
    {
        con = pet_htable_search(map->ipv4_table, (uintptr_t)&ipv4_tuple);

        if (con) {
           get_tcp_con(con);
        }
    }
    pthread_mutex_unlock(&(map->lock));

    if (con) {
        pthread_mutex_lock(&(con->con_lock));
    }

    return con;
}


struct tcp_connection *
get_and_lock_tcp_con_from_sock(struct tcp_con_map * map,
                               struct socket      * sock)
{
    struct tcp_connection * con = NULL;

    pthread_mutex_lock(&(map->lock));
    {
        con = pet_htable_search(map->sock_table, (uintptr_t)sock);

        if (con) {
            get_tcp_con(con);
        }
    }
    pthread_mutex_unlock(&(map->lock));

    if (con) {
        pthread_mutex_lock(&(con->con_lock));
    }

    return con;
}

struct tcp_connection *
create_ipv4_tcp_con(struct tcp_con_map * map,
                    struct ipv4_addr   * local_ip,
                    struct ipv4_addr   * remote_ip,
                    uint16_t             local_port,
                    uint16_t             remote_port)
{
    struct tcp_connection * new_con   = NULL;

    int ret = 0;

    new_con = pet_malloc(sizeof(struct tcp_connection));

    new_con->net_type               = IPV4_NETWORK;
    new_con->ipv4_tuple.local_ip    = ipv4_addr_clone(local_ip);
    new_con->ipv4_tuple.remote_ip   = ipv4_addr_clone(remote_ip);
    new_con->ipv4_tuple.local_port  = local_port;
    new_con->ipv4_tuple.remote_port = remote_port;
    new_con->ref_cnt                = 1;

    pthread_mutex_init(&(new_con->con_lock), NULL);

    pthread_mutex_lock(&(map->lock));
    {
        ret = pet_htable_insert(map->ipv4_table, (uintptr_t)&(new_con->ipv4_tuple), (uintptr_t)new_con);
    }
    pthread_mutex_unlock(&(map->lock));

    if (ret == -1) {
        log_error("Could not create new TCP connection\n");
        goto err;
    }

    
    /* We return a locked reference */
    //    new_con->ref_cnt++;
    get_tcp_con(new_con);
    pthread_mutex_lock(&(new_con->con_lock));

    return new_con;
err:

    if (new_con) __free_tcp_connection(new_con);

    return NULL;

}

int 
add_sock_to_tcp_con(struct tcp_con_map    * map,
                    struct tcp_connection * con, 
                    struct socket         * sock)
{
    int ret = 0;

    con->sock = pet_get_socket(sock);

    pthread_mutex_lock(&(map->lock));
    {
        ret = pet_htable_insert(map->sock_table, (uintptr_t)sock, (uintptr_t)con);
    }
    pthread_mutex_unlock(&(map->lock));


    if (ret == -1) {
        log_error("Could not add socket to connection\n");
        return -1;
    }

    return ret;
}

void
remove_tcp_con(struct tcp_con_map    * map,
               struct tcp_connection * con)
{
    pthread_mutex_lock(&(map->lock));
    {
        pet_htable_remove(map->ipv4_table, (uintptr_t)&(con->ipv4_tuple));
        if (con->sock) pet_htable_remove(map->sock_table, (uintptr_t)con->sock);
    }
    pthread_mutex_unlock(&(map->lock));

    put_tcp_con(con);

    return;
}


void
free_tcp_con_map(struct tcp_con_map * map)
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

struct tcp_con_map *
create_tcp_con_map()
{
    struct tcp_con_map * con_map = pet_malloc(sizeof(struct tcp_con_map));

    con_map->ipv4_table = pet_create_htable(0, __ipv4_tuple_hash_fn, __ipv4_tuple_eq_fn, NULL, NULL);
    //    con_map->ipv6_table = pet_create_htable(0, __ipv6_tuple_hash_fn, __ipv6_tuple_eq_fn, NULL, NULL);
    con_map->sock_table = pet_create_htable(0, pet_hash_ptr, pet_cmp_ptr, NULL, NULL);

    pthread_mutex_init(&(con_map->lock), NULL);

    return con_map;
}