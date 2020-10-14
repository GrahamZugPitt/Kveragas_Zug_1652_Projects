/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <petlib/pet_log.h>
#include <petlib/pet_util.h>

#include <drivers/pet_driver.h>

#include <petnet.h>

#include "packet_pool.h"
#include "packet.h"
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"

#include <arpa/inet.h>



static struct eth_raw_hdr *
__get_eth_hdr(struct packet * pkt)
{
	struct eth_raw_hdr * eth_hdr = (struct eth_raw_hdr *)pkt->buf;

	pkt->layer_2_type    = ETHERNET_PKT;
	pkt->layer_2_hdr     = eth_hdr;
	pkt->layer_2_hdr_len = sizeof(struct eth_raw_hdr);

	return eth_hdr;
}

static struct eth_raw_hdr *
__make_eth_hdr(struct packet * pkt)
{
	pkt->layer_2_type    = ETHERNET_PKT;
	pkt->layer_2_hdr     = pet_malloc(sizeof(struct eth_raw_hdr));
	pkt->layer_2_hdr_len = sizeof(struct eth_raw_hdr);

	return (struct eth_raw_hdr *)(pkt->layer_2_hdr);
}


pet_json_obj_t 
ethernet_hdr_to_json(struct eth_raw_hdr * hdr)
{
	pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

	struct mac_addr * src_mac = NULL;
	struct mac_addr * dst_mac = NULL;

	src_mac = mac_addr_from_octets(hdr->src_mac);
	dst_mac = mac_addr_from_octets(hdr->dst_mac);

	hdr_json = pet_json_new_obj("Ethernet Header");

	if (hdr_json == PET_JSON_INVALID_OBJ) {
		log_error("Could not create Ethernet Header JSON\n");
		goto err;
	}

	mac_addr_to_json(src_mac, hdr_json, "src_mac");
	mac_addr_to_json(dst_mac, hdr_json, "dst_mac");
	pet_json_add_u16(hdr_json, "ether_type", ntohs(hdr->ether_type));

	free_mac_addr(src_mac);
	free_mac_addr(dst_mac);

	return hdr_json;

err:
	if (src_mac) free_mac_addr(src_mac);
	if (dst_mac) free_mac_addr(dst_mac);

	return PET_JSON_INVALID_OBJ;
}

void
print_ethernet_hdr(struct eth_raw_hdr * eth_hdr)
{
	pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

	char * json_str = NULL;

	hdr_json = ethernet_hdr_to_json(eth_hdr);

	if (hdr_json == PET_JSON_INVALID_OBJ) {
		log_error("Could not serialize Ethernet Header to JSON\n");
		return;
	}

	json_str = pet_json_serialize(hdr_json);

	pet_printf("\"Ethernet Header\": %s\n", json_str);

	pet_free(json_str);
	pet_json_free(hdr_json);

	return;
}

int
ethernet_pkt_rx(struct packet * pkt)
{
	struct eth_raw_hdr * eth_hdr = __get_eth_hdr(pkt);

	struct mac_addr * dst_mac     = NULL;

	int ret = -1;

	dst_mac = mac_addr_from_octets(eth_hdr->dst_mac);

	if ( (mac_addr_is_broadcast(dst_mac)             == 0) && 
		 (mac_addr_compare(dst_mac, petnet_state->mac_addr) != 0) ) {
		
		free_mac_addr(dst_mac);

		return 0;
	}

    if (petnet_state->debug_enable) {
		pet_printf("Received Ethernet Frame\n");
		print_ethernet_hdr(eth_hdr);
	}

    switch (ntohs(eth_hdr->ether_type)) {
		case ETHERTYPE_ARP:
			ret = arp_pkt_rx(pkt);
			break;
		case ETHERTYPE_IPV4:
			ret = ipv4_pkt_rx(pkt);
			break;
		case ETHERTYPE_IPV6:
		//	ret = ipv6_pkt_rx(state, pkt);
			break;
		case ETHERTYPE_RARP:
			break;
		default:
			log_error("Unhandled Ethernet Packet (type=%x)\n", ntohs(eth_hdr->ether_type));
			break;
	}

    return ret;
}

int
ethernet_pkt_tx(struct packet   * pkt,
                struct mac_addr * dst_mac)
{
	struct eth_raw_hdr * eth_hdr = __make_eth_hdr(pkt);

	mac_addr_to_octets(dst_mac,         eth_hdr->dst_mac);
	mac_addr_to_octets(petnet_state->mac_addr, eth_hdr->src_mac);

	switch(pkt->layer_3_type) {
		case ARP_PKT:
			eth_hdr->ether_type = htons(ETHERTYPE_ARP);
			break;
		case IPV4_PKT:
			eth_hdr->ether_type = htons(ETHERTYPE_IPV4);
			break;
		case IPV6_PKT:
			eth_hdr->ether_type = htons(ETHERTYPE_IPV6);
			break;
		default:
			log_error("Unhandled Packet Type\n");
			return -1;

	}

	return pet_driver_tx(pkt);
	
}