/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <petlib/pet_list.h>
#include <petlib/pet_util.h>
#include <petlib/pet_log.h>

#include <petnet.h>


#include "packet_pool.h"
#include "packet.h"

#include <pthread.h>

struct petnet_pkt_pool {

    struct list_head pkt_free_list;

    pthread_mutex_t lock;

};

static void 
__free_pool(struct petnet_pkt_pool * pool)
{
    struct packet * iter_pkt = NULL;
    struct packet * temp_pkt = NULL;

    list_for_each_entry_safe(iter_pkt, temp_pkt, &(pool->pkt_free_list), list_node) {
        free_packet(iter_pkt);
    }
}


int
pkt_pool_init(struct petnet * state)
{
    struct petnet_pkt_pool * pool = NULL;

    uint32_t i = 0;


    pool = pet_malloc(sizeof(struct petnet_pkt_pool));


    if (pool == NULL) {
        log_error("Could not allocate packet pool\n");
        return -1;
    }

    list_head_init(&(pool->pkt_free_list));
    pthread_mutex_init(&(pool->lock), NULL);



    for (i = 0; i < state->pkt_pool_size; i++) {
        struct packet * pkt = create_packet(state->device_mtu);

        if (pkt == NULL) {
            log_error("Could not allocate packet pool\n");
            goto err;
        }

        list_add_tail(&(pkt->list_node), &(pool->pkt_free_list));
    }

    state->pkt_pool = pool;


    return 0;

    
err:
    if (!list_empty(&(pool->pkt_free_list))) {
        __free_pool(pool);
    }


    return -1;
}

static void
__pool_put(struct petnet_pkt_pool * pool, 
           struct packet          * pkt)
{
    list_add(&(pkt->list_node), &(pool->pkt_free_list));

    return;
}


void
pkt_pool_put(struct petnet * state,
             struct packet * pkt)
{
    struct petnet_pkt_pool * pool = (struct petnet_pkt_pool *)(state->pkt_pool);


    release_packet(pkt);

    pthread_mutex_lock(&(pool->lock));
    {
        __pool_put(pool, pkt);
    }
    pthread_mutex_unlock(&(pool->lock));

    return;
}


static struct packet * 
__pool_get(struct petnet_pkt_pool * pool)
{
    struct packet * pkt = NULL;

    if (list_empty(&(pool->pkt_free_list))) {
        log_error("Packet pool is depleted\n");
        return NULL;
    }

    pkt = list_first_entry(&(pool->pkt_free_list), struct packet, list_node);

    list_del(&(pkt->list_node));

    return pkt;
}

struct packet *
pkt_pool_get( struct petnet * state )
{
    struct petnet_pkt_pool * pool = (struct petnet_pkt_pool *)(state->pkt_pool);
    struct packet * pkt = NULL;

    pthread_mutex_lock(&(pool->lock));
    {
        pkt = __pool_get(pool);
    }
    pthread_mutex_unlock(&(pool->lock));

    return pkt;
}