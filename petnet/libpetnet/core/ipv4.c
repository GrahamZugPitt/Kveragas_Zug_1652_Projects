/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#include <petnet.h>


#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_json.h>

#include "packet.h"
#include "ipv4.h"
#include "icmp.h"
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include "ethernet.h"

#include <util/mac_address.h>
#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

int 
ipv4_expected_hdr_len()
{
    return 20;
}


static struct ipv4_raw_hdr *
__get_ipv4_hdr(struct packet * pkt)
{
	struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len;

    pkt->layer_3_type    = IPV4_PKT;
	pkt->layer_3_hdr     = ipv4_hdr;
	pkt->layer_3_hdr_len = ipv4_hdr->header_len * 4;

	return ipv4_hdr;
}


static struct ipv4_raw_hdr *
__make_ipv4_hdr(struct packet * pkt, 
                uint32_t        option_len)
{
    pkt->layer_3_type    = IPV4_PKT;
	pkt->layer_3_hdr     = pet_malloc(sizeof(struct ipv4_raw_hdr) + option_len);
	pkt->layer_3_hdr_len = sizeof(struct ipv4_raw_hdr) + option_len;

	return (struct ipv4_raw_hdr *)(pkt->layer_3_hdr);
}


pet_json_obj_t
ipv4_hdr_to_json(struct ipv4_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    struct ipv4_addr * src_ip = ipv4_addr_from_octets(hdr->src_ip);
    struct ipv4_addr * dst_ip = ipv4_addr_from_octets(hdr->dst_ip);

    hdr_json = pet_json_new_obj("IPV4 Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create IPV4 Header JSON\n");
        goto err;
    }

    pet_json_add_u8 (hdr_json, "version",       hdr->version);
    pet_json_add_u8 (hdr_json, "header length", hdr->header_len * 4);
    pet_json_add_u8 (hdr_json, "dscp",          hdr->dscp);
    pet_json_add_u8 (hdr_json, "ecn",           hdr->ecn);
    pet_json_add_u16(hdr_json, "total length",  ntohs(hdr->total_len));
    pet_json_add_u16(hdr_json, "frag_id",       ntohs(hdr->frag_id));
    pet_json_add_u16(hdr_json, "flags",         hdr->flags);
    pet_json_add_u16(hdr_json, "frag_offset",   ntohs(hdr->frag_offset));
    pet_json_add_u8 (hdr_json, "ttl",           hdr->ttl);
    pet_json_add_u8 (hdr_json, "proto",         hdr->proto);
    pet_json_add_u16(hdr_json, "checksum",      hdr->checksum);

    ipv4_addr_to_json(src_ip, hdr_json, "src_ip");
    ipv4_addr_to_json(dst_ip, hdr_json, "dst_ip");

    free_ipv4_addr(src_ip);
    free_ipv4_addr(dst_ip);

    return hdr_json;
err:   
    if (src_ip) free_ipv4_addr(src_ip);
    if (dst_ip) free_ipv4_addr(dst_ip);

    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}

void
print_ipv4_header(struct ipv4_raw_hdr * ipv4_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = ipv4_hdr_to_json(ipv4_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize IPV4 Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"IPV4 Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;
}

static int
__sanity_check_hdr(struct ipv4_raw_hdr * ipv4_hdr) 
{
    // Validate Checksum
    
    // Header_len >= 5
 
    return 0;
}

int 
ipv4_pkt_rx(struct packet * pkt)
{
    struct ipv4_raw_hdr * ipv4_hdr = __get_ipv4_hdr(pkt);
    int ret = 0;

    if (__sanity_check_hdr(ipv4_hdr) == -1) {
        log_error("Invalid IPv4 Header\n");
        return -1;
    }

    if (petnet_state->debug_enable) {
        log_debug("Received IPv4 Packet\n");
        print_ipv4_header(ipv4_hdr);
    }

    switch (ipv4_hdr->proto) {
        case IPV4_PROTO_ICMP:
            ret = icmp_pkt_rx(pkt);
            break;
        case IPV4_PROTO_TCP:
            ret = tcp_pkt_rx(pkt);
            break;
        case IPV4_PROTO_UDP:
            ret = udp_pkt_rx(pkt);
            break;
        default:
            log_error("Unhandled IPV4 Packet Protocol (%d)\n", ipv4_hdr->proto);
            break;
    }

    return ret;
}


int
ipv4_pkt_tx(struct packet    * pkt, 
            struct ipv4_addr * dst_addr)
{
    struct ipv4_raw_hdr * ipv4_hdr = NULL;

    int ret = 0;

    ipv4_hdr = __make_ipv4_hdr(pkt, 0);

    ipv4_hdr->version     = 4;
    ipv4_hdr->header_len  = pkt->layer_3_hdr_len / 4;
    ipv4_hdr->dscp        = 0;
    ipv4_hdr->ecn         = 0;
    ipv4_hdr->total_len   = htons(pkt->payload_len + pkt->layer_4_hdr_len + pkt->layer_3_hdr_len);
    ipv4_hdr->frag_id     = 0;
    ipv4_hdr->flags       = 0;
    ipv4_hdr->frag_offset = 0;
    ipv4_hdr->ttl         = 16; //?
    ipv4_hdr->checksum    = 0;
    ipv4_addr_to_octets(dst_addr,              ipv4_hdr->dst_ip);
    ipv4_addr_to_octets(petnet_state->addr_v4, ipv4_hdr->src_ip);

    switch(pkt->layer_4_type) {
        case TCP_PKT:
            ipv4_hdr->proto = IPV4_PROTO_TCP;
            break;
        case UDP_PKT:
            ipv4_hdr->proto = IPV4_PROTO_UDP;
            break;
        case ICMP_PKT:
            ipv4_hdr->proto = IPV4_PROTO_ICMP;
            break;
        default:
            log_error("Invalid IPV4 Protocol\n");
            goto err;
    }

    ipv4_hdr->checksum = calculate_checksum(pkt->layer_3_hdr, pkt->layer_3_hdr_len / 2);



    /*
        log_debug("Transmitting IPv4 Packet\n");
        print_ipv4_header(ipv4_hdr);
    */
    
    ret = arp_lookup_and_tx(pkt, dst_addr);

    if (ret == -1) {
        log_error("Error during ARP lookup request\n");
        goto err;
    }

    return 0;

err:
    return -1;
}