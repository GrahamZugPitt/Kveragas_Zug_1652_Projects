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
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"


extern int petnet_errno;

struct tcp_state {
    struct tcp_con_map * con_map;
};



static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}


static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt, 
               uint32_t        option_len)
{
    pkt->layer_4_type    = TCP_PKT; //Labels packet as TCP packet
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len); //literally putting the memory inside the layer 4 header part of the packet
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len; //Determines header length

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
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

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}





int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{
	struct tcp_state      * tcp_state = petnet_state->tcp_state;
	struct tcp_connection* con = create_new_listening_connection(tcp_state->con_map, sock, local_addr, local_port);
	//struct tcp_connection* con_2 = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);
	(void)con;
	put_and_unlock_tcp_con(con);
	return 0;
}

int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * local_addr, 
                 uint16_t           local_port,
                 struct ipv4_addr * remote_addr,
                 uint16_t           remote_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection* listening = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map,local_addr,local_addr,local_port,local_port);
    struct tcp_connection* con;
    if(listening->con_state == LISTEN){
	put_and_unlock_tcp_con(listening);
    	con = create_ipv4_tcp_con(tcp_state->con_map,local_addr,remote_addr,local_port,remote_port);
	/*con->con_state = SYN_RCVD;
        con->seq_num_recieved = hdr->seq_num; 
        con->ack_num_recieved = hdr->ack_num;
    	con->recv_win_recieved = hdr->recv_win;*/
	
	put_and_unlock_tcp_con(con);
	return 0;
	}
    pet_printf("Port not listening.");
    return -1;
}

int send_pkt(struct tcp_connection * con){
	/*struct tcp_state* tcp_state = petnet_state->tcp_state;
	struct packet* pkt       = NULL;
	struct tcp_raw_hdr* tcp_hdr   = NULL;	*/
	return 0;	
}

int
tcp_send(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con	      = get_and_lock_tcp_con_from_sock(tcp_state->con_map,sock);

	if(con->con_state == SYN_RCVD){
		//send_pkt(con); 
		pet_printf("");
	}
	if(con->con_state != ESTABLISHED){
		log_error("TCP connection is not established \n");
		goto err;
	}
	
	//send_pkt(con);
	put_and_unlock_tcp_con(con);
	
	return 0;

	err:
		if (con) put_and_unlock_tcp_con(con);
		return -1;

    (void)tcp_state; // delete me

    return -1;
}



/* Petnet assumes SO_LINGER semantics, so if we'ere here there is no pending write data */
int
tcp_close(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
  
    (void)tcp_state; // delete me

    return 0;
}






int 
tcp_pkt_rx(struct packet * pkt) //TODO: Actually get the payload, all this does right now is establish a connection from the initial SYN packet
{
    if (pkt->layer_3_type == IPV4_PKT) {
   
        struct tcp_state* tcp_state = petnet_state->tcp_state;
	struct tcp_connection* con = NULL;
	struct tcp_connection* con_check_initial = NULL;
        struct ipv4_raw_hdr * ipv4_hdr  = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
        struct tcp_raw_hdr  * tcp_hdr   = NULL;
        void                * payload   = NULL;

	struct ipv4_addr * src_ip = NULL;
	struct ipv4_addr * dst_ip = NULL;

	int ret = 0;

    tcp_hdr  = __get_tcp_hdr(pkt);
    payload  = __get_payload(pkt);

    //if (petnet_state->debug_enable) {
        pet_printf("I recieved the packet.\n");
        print_tcp_header(tcp_hdr);
    //}

    src_ip   = ipv4_addr_from_octets(ipv4_hdr->src_ip);
    dst_ip   = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
    con_check_initial = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map,dst_ip,dst_ip,ntohs(tcp_hdr->dst_port),ntohs(tcp_hdr->dst_port)); //gotta free it
    if(con_check_initial != NULL){
		put_and_unlock_tcp_con(con_check_initial);
		if(tcp_hdr->flags.SYN == 1){
			tcp_connect_ipv4(con_check_initial->sock, dst_ip, ntohs(tcp_hdr->dst_port), src_ip, ntohs(tcp_hdr->src_port));
			//con->con_state = SYN_RCVD;
			return 0;
		}
		pet_printf("Client attempted to contact an open port without the SYN flag.");
		return -1;
	}
    put_and_unlock_tcp_con(con_check_initial);
    con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));
	(void)con;
	(void)payload;
	(void)src_ip;
	return ret;
    }

    return -1;
}

int 
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));

    state->con_map  = create_tcp_con_map();

    petnet_state->tcp_state = state;
    
    return 0;
}
