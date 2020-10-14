/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>

#include <petlib/pet_util.h>

#include "packet.h"



struct packet * 
create_packet(uint32_t pkt_size)
{
    struct packet * pkt = NULL;

    pkt = pet_malloc(sizeof(struct packet) + pkt_size);
    pkt->buf_size = pkt_size;

    return pkt;
}

struct packet *
create_empty_packet()
{
    struct packet * pkt = NULL;
    
    pkt = pet_malloc(sizeof(struct packet));

    return pkt;

}


struct packet * 
create_raw_packet(uint8_t  * raw_data, 
                  uint32_t   raw_data_len)
{
    struct packet * pkt = NULL;

    pkt = pet_malloc(sizeof(struct packet) + raw_data_len);

    memcpy(pkt->buf, raw_data, raw_data_len);
    pkt->buf_len  = raw_data_len;
    pkt->buf_size = raw_data_len;


    return pkt;
}

#define IN_RANGE(ptr, min, max) (((void *)ptr >= (void *)min) && ((void *)ptr < (void *)max))

void 
free_packet(struct packet * pkt)
{

    if ((pkt->layer_2_hdr != NULL) &&
        !IN_RANGE(pkt->layer_2_hdr, pkt->buf, pkt->buf + pkt->buf_size)) {
        //  pet_printf("freeing layer 2 hdr (%p) (%p)\n", pkt->layer_2_hdr, pkt->buf);
        pet_free(pkt->layer_2_hdr);
    }

    if ((pkt->layer_3_hdr != NULL) &&
        !IN_RANGE(pkt->layer_3_hdr, pkt->buf, pkt->buf + pkt->buf_size)) {
        //  pet_printf("freeing layer 3 hdr\n");
        pet_free(pkt->layer_3_hdr);
    }

    if ((pkt->layer_4_hdr != NULL) &&
        !IN_RANGE(pkt->layer_4_hdr, pkt->buf, pkt->buf + pkt->buf_size)) {
        //  pet_printf("freeing layer 4 hdr\n");
        pet_free(pkt->layer_4_hdr);
    }

    if ((pkt->payload != NULL) &&
        !IN_RANGE(pkt->payload, pkt->buf, pkt->buf + pkt->buf_size)) {
        //  pet_printf("freeing payload\n");
        pet_free(pkt->payload);
    }


    pet_free(pkt);
}

void 
release_packet(struct packet * pkt)
{

    if ((pkt->layer_2_hdr != NULL) &&
        !IN_RANGE(pkt->layer_2_hdr, pkt->buf, pkt->buf + pkt->buf_size)) {
        pet_free(pkt->layer_2_hdr);
    }
    pkt->layer_2_hdr     = NULL;
    pkt->layer_2_hdr_len = 0;

    if ((pkt->layer_3_hdr != NULL) &&
        !IN_RANGE(pkt->layer_3_hdr, pkt->buf, pkt->buf + pkt->buf_size)) {
        pet_free(pkt->layer_3_hdr);
    }
    pkt->layer_3_hdr     = NULL;
    pkt->layer_3_hdr_len = 0;

    if ((pkt->layer_4_hdr != NULL) &&
        !IN_RANGE(pkt->layer_4_hdr, pkt->buf, pkt->buf + pkt->buf_size)) {
        pet_free(pkt->layer_4_hdr);
    }
    pkt->layer_4_hdr     = NULL;
    pkt->layer_4_hdr_len = 0;
    
    if ((pkt->payload != NULL) &&
        !IN_RANGE(pkt->payload, pkt->buf, pkt->buf + pkt->buf_size)) {
        pet_free(pkt->payload);
    }
    pkt->payload     = NULL;
    pkt->payload_len = 0;

    pkt->buf_len = 0;
    memset(pkt->buf, 0, pkt->buf_size);

    return;
}
