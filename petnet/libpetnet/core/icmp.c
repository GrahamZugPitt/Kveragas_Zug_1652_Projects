/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#include <string.h>


#include <petnet.h>


#include <petlib/pet_util.h>
#include <petlib/pet_log.h>

#include "packet.h"
#include "icmp.h"
#include "ipv4.h"

#include <util/mac_address.h>
#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#define ICMP_TYPE_ECHO_REPLY     0
#define ICMP_TYPE_ECHO_REQUEST   8
#define ICMP_TYPE_TIME_EXCEEDED  11

static struct icmp_raw_hdr *
__get_icmp_hdr(struct packet * pkt)
{
	struct icmp_raw_hdr * icmp_hdr = pkt->layer_3_hdr + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = ICMP_PKT;
	pkt->layer_4_hdr     = icmp_hdr;
	pkt->layer_4_hdr_len = sizeof(struct icmp_raw_hdr);

	return icmp_hdr;
}


static struct icmp_raw_hdr *
__make_icmp_hdr(struct packet * pkt)
{
    pkt->layer_4_type    = ICMP_PKT;
	pkt->layer_4_hdr     = pet_malloc(sizeof(struct icmp_raw_hdr));
	pkt->layer_4_hdr_len = sizeof(struct icmp_raw_hdr);

	return (struct icmp_raw_hdr *)(pkt->layer_4_hdr);
}



pet_json_obj_t
icmp_hdr_to_json(struct icmp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;


    hdr_json = pet_json_new_obj("ICMP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create IPV4 Header JSON\n");
        goto err;
    }

    pet_json_add_u8 (hdr_json, "type",       hdr->type);
    pet_json_add_u8 (hdr_json, "code",       hdr->code);
    pet_json_add_u16(hdr_json, "checksum",   hdr->checksum);
    pet_json_add_u32(hdr_json, "aux_header", hdr->aux_hdr);

    return hdr_json;
err:   


    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}

void
print_icmp_header(struct icmp_raw_hdr * icmp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = icmp_hdr_to_json(icmp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize ICMP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"ICMP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;
}

static int
__handle_echo_request(struct packet       * pkt,
                      struct icmp_raw_hdr * icmp_hdr)
{
    struct ipv4_raw_hdr      * ipv4_hdr      = pkt->layer_3_hdr;
    struct ipv4_addr         * src_ip        = ipv4_addr_from_octets(ipv4_hdr->src_ip);

    struct packet            * reply_pkt     = NULL;
    struct icmp_raw_hdr      * reply_hdr     = NULL;

    uint32_t  data_len   = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);
    uint8_t * reply_data = NULL;

    reply_pkt = create_empty_packet();

    if (reply_pkt == NULL) {
        log_error("Could not create ICMP ECHO Reply Packet\n");
        goto err;
    }

    // Basic sanity check on the received packets reported size
    if (data_len > (petnet_state->device_mtu - (pkt->layer_4_hdr_len + pkt->layer_3_hdr_len + pkt->layer_2_hdr_len))) {
        log_error("Invalid IP Packet length\n");
        goto err;
    }

    reply_data = pet_malloc(data_len);

    memcpy(reply_data, pkt->layer_4_hdr + pkt->layer_4_hdr_len, data_len);

    reply_hdr = __make_icmp_hdr(reply_pkt);


    reply_hdr->type                  = ICMP_TYPE_ECHO_REPLY;
    reply_hdr->code                  = 0;
    reply_hdr->icmp_echo_hdr.id      = icmp_hdr->icmp_echo_hdr.id;
    reply_hdr->icmp_echo_hdr.seq_num = icmp_hdr->icmp_echo_hdr.seq_num;

    reply_pkt->payload               = reply_data;
    reply_pkt->payload_len           = data_len;

    reply_hdr->checksum              = calculate_checksum_begin((uint16_t *)reply_hdr, sizeof(struct icmp_raw_hdr) / 2);
    reply_hdr->checksum              = calculate_checksum_finalize(reply_hdr->checksum, reply_pkt->payload, reply_pkt->payload_len / 2);



    ipv4_pkt_tx(reply_pkt, src_ip);


    free_ipv4_addr(src_ip);

    return 0;

err:
    if (src_ip)     free_ipv4_addr(src_ip);

    if (reply_pkt)  free_packet(reply_pkt);
    if (reply_data) pet_free(reply_data);


    return -1;
}

int
icmp_pkt_rx(struct packet  * pkt)
{
    struct icmp_raw_hdr * icmp_hdr = __get_icmp_hdr(pkt);

    int ret = -1;

    if (petnet_state->debug_enable) {
        pet_printf("Received ICMP Packet\n");
        print_icmp_header(icmp_hdr);
    }

    switch (icmp_hdr->type) {
        case ICMP_TYPE_ECHO_REPLY: 
            break;
        case ICMP_TYPE_ECHO_REQUEST:
            ret = __handle_echo_request(pkt, icmp_hdr);
            break;
        case ICMP_TYPE_TIME_EXCEEDED:
            break;
        default:
            log_error("Unhandled ICMP Type (%d)\n", icmp_hdr->type);
            break;
    }   


    return ret;
}