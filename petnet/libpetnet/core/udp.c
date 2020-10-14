/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_json.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "udp.h"
#include "udp_endpoint.h"
#include "packet.h"
#include "socket.h"

struct udp_state {
    struct udp_endpoint_map * map;
};


static struct udp_raw_hdr *
__get_udp_hdr(struct packet * pkt)
{
	struct udp_raw_hdr * udp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = UDP_PKT;
	pkt->layer_4_hdr     = udp_hdr;
	pkt->layer_4_hdr_len = sizeof(struct udp_raw_hdr);

	return udp_hdr;
}


static struct udp_raw_hdr *
__make_udp_hdr(struct packet * pkt)
{
    pkt->layer_4_type    = UDP_PKT;
	pkt->layer_4_hdr     = pet_malloc(sizeof(struct udp_raw_hdr));
	pkt->layer_4_hdr_len = sizeof(struct udp_raw_hdr);

	return (struct udp_raw_hdr *)(pkt->layer_4_hdr);
}

static void *
__get_payload(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

}


static uint16_t 
__calculate_chksum(struct udp_endpoint * endpoint,
                   struct ipv4_addr    * remote_addr,
                   struct packet       * pkt)
{
    struct ipv4_pseudo_hdr hdr;
    uint16_t checksum = 0;

    memset(&hdr, 0, sizeof(struct ipv4_pseudo_hdr));

    ipv4_addr_to_octets(endpoint->ipv4_tuple.local_ip,  hdr.src_ip);
    ipv4_addr_to_octets(remote_addr,                    hdr.dst_ip);

    hdr.proto  = IPV4_PROTO_UDP;
    hdr.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

    checksum = calculate_checksum_begin(&hdr, sizeof(struct ipv4_pseudo_hdr) / 2);
    checksum = calculate_checksum_continue(checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);
    checksum = calculate_checksum_continue(checksum, pkt->payload,     pkt->payload_len     / 2);


    /* 
     * If there is an odd number of data bytes we have to include a 0-byte after the the last byte 
     */
    if ((pkt->payload_len % 2) != 0) {
        uint16_t tmp = *(uint8_t *)(pkt->payload + pkt->payload_len - 1);

        checksum = calculate_checksum_finalize(checksum, &tmp, 1);
    } else {
        checksum = calculate_checksum_finalize(checksum, NULL, 0);
    }

    return checksum;
}

pet_json_obj_t
udp_hdr_to_json(struct udp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("UDP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create udp Header JSON\n");
        goto err;
    }

    pet_json_add_u16(hdr_json, "src port", ntohs(hdr->src_port));
    pet_json_add_u16(hdr_json, "dst port", ntohs(hdr->dst_port));
    pet_json_add_u16(hdr_json, "length",   ntohs(hdr->length));
    pet_json_add_u16(hdr_json, "checksum", ntohs(hdr->checksum));

    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_udp_header(struct udp_raw_hdr * udp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = udp_hdr_to_json(udp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize UDP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"UDP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}

int 
udp_bind(struct socket    * sock, 
         struct ipv4_addr * local_addr,
         uint16_t           local_port)
{
    struct udp_state    * udp_state = petnet_state->udp_state;
    struct udp_endpoint * endpoint  = NULL;

    endpoint = create_ipv4_udp_endpoint(udp_state->map, sock, local_addr, local_port);

    if (endpoint == NULL) {
        /* This should never happen */
        pet_socket_error(sock, EINVAL);
        goto err;
    }

    put_and_unlock_udp_endpoint(endpoint);

    return 0;


err:

    if (endpoint) put_and_unlock_udp_endpoint(endpoint);

    return -1;
}

int
udp_close(struct socket * sock)
{
    struct udp_state    * udp_state = petnet_state->udp_state;  
    struct udp_endpoint * endpoint  = get_and_lock_udp_endpoint_from_sock(udp_state->map, sock);

    if (endpoint == NULL) {
        pet_socket_error(sock, EAGAIN);
        goto err;
    }

    remove_udp_endpoint(udp_state->map, endpoint);

    put_and_unlock_udp_endpoint(endpoint);

    return 0;

err:
    if (endpoint) put_and_unlock_udp_endpoint(endpoint);

    return -1;
}



int 
udp_send_datagram(struct socket    * sock,
                  void             * buf,
                  size_t             len,
                  struct ipv4_addr * remote_addr,
                  uint16_t           remote_port)
{
    struct udp_state    * udp_state = petnet_state->udp_state;
    struct udp_endpoint * endpoint  = get_and_lock_udp_endpoint_from_sock(udp_state->map, sock);
    struct packet       * pkt       = NULL;
    struct udp_raw_hdr  * udp_hdr   = NULL;

    uint32_t data_capacity = petnet_state->device_mtu - (sizeof(struct eth_raw_hdr) + ipv4_expected_hdr_len() + sizeof(struct udp_raw_hdr));

    if (endpoint == NULL) {
        /* Should never happen */
        pet_socket_error(sock, EAGAIN);
        goto err;
    }

    if (len > data_capacity) {
        pet_socket_error(sock, EMSGSIZE);
        goto err;
    }

    pkt     = create_empty_packet();
    udp_hdr = __make_udp_hdr(pkt);

    udp_hdr->src_port = htons(endpoint->ipv4_tuple.local_port);
    udp_hdr->dst_port = htons(remote_port);
    udp_hdr->length   = htons(sizeof(struct udp_raw_hdr) + len);
    udp_hdr->checksum = 0;

    pkt->payload_len = len;
    pkt->payload     = pet_malloc(len);

    memcpy(pkt->payload, buf, pkt->payload_len);

    udp_hdr->checksum = __calculate_chksum(endpoint, remote_addr, pkt);

    ipv4_pkt_tx(pkt, remote_addr);

    put_and_unlock_udp_endpoint(endpoint);

    return 0;

err:
    if (pkt)      free_packet(pkt);
    if (endpoint) put_and_unlock_udp_endpoint(endpoint);

    return -1;
}


static int
__udp_pkt_rx_ipv4(struct packet * pkt)
{
    struct udp_state    * udp_state = petnet_state->udp_state;
    struct udp_endpoint * endpoint  = NULL;
    struct ipv4_raw_hdr * ipv4_hdr  = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
    struct udp_raw_hdr  * udp_hdr   = NULL;
    void                * payload   = NULL;

    struct ipv4_addr * src_ip = NULL;
    struct ipv4_addr * dst_ip = NULL;

    int ret = 0;

    udp_hdr  = __get_udp_hdr(pkt);
    payload  = __get_payload(pkt);


    if (petnet_state->debug_enable) {
        pet_printf("Received UDP Datagram\n");
        print_udp_header(udp_hdr);
    }

    src_ip   = ipv4_addr_from_octets(ipv4_hdr->src_ip);
    dst_ip   = ipv4_addr_from_octets(ipv4_hdr->dst_ip);

    endpoint = get_and_lock_udp_endpoint_from_ipv4(udp_state->map,
                                                   dst_ip,
                                                   ntohs(udp_hdr->dst_port));


    if (endpoint == NULL) {
        log_error("Could not find UDP endpoint\n");
        goto out;
    }


    ret = pet_socket_received_datagram(endpoint->sock, 
                                       payload, 
                                       pkt->payload_len, 
                                       src_ip, 
                                       ntohs(udp_hdr->src_port));


    if (ret == -1) {
        // Doesn't really matter so just ignore the error
        log_error("Failed to receive datagram\n");
        goto out;
    }

out:
    if (endpoint) put_and_unlock_udp_endpoint(endpoint);

    return 0;
}



int 
udp_pkt_rx(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        return __udp_pkt_rx_ipv4(pkt);
    }



    return -1;
}

int 
udp_init(struct petnet * petnet_state)
{
    struct udp_state * state = pet_malloc(sizeof(struct udp_state));

    state->map = create_udp_endpoint_map();

    petnet_state->udp_state = state;

    return 0;
}