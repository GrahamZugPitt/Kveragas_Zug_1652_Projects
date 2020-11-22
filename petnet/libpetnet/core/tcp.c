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
#include <unistd.h>

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

#define EZ pet_printf("Hooty Hoo");


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
static inline uint32_t 
__get_payload_len(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload_len;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return 0;
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

uint16_t
calculate_checksum_continue_flip(uint16_t   checksum,
                            void     * data,
                            uint32_t   length_in_words)
{
    uint32_t   scratch   = checksum;
    uint16_t * cast_data = data;

    uint32_t i = 0;

    for (i = 0; i < length_in_words; i++) {
        scratch += htons(cast_data[i]);

        // Wrap overflow
        if (scratch & 0xffff0000) {
            scratch &= 0x0000ffff;
            scratch += 1;
        }
    }

    return (uint16_t)scratch;
}

static uint16_t 
_calculate_checksum(struct ipv4_addr    * local_addr,
                   struct ipv4_addr    * remote_addr,
                   struct packet       * pkt)
{


    struct ipv4_pseudo_hdr hdr;
    uint16_t checksum = 0;
    memset(&hdr, 0, sizeof(struct ipv4_pseudo_hdr));

    ipv4_addr_to_octets(local_addr,  hdr.src_ip);
    ipv4_addr_to_octets(remote_addr,                    hdr.dst_ip);

    hdr.proto  = IPV4_PROTO_TCP;
    hdr.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

    checksum = calculate_checksum_begin(&hdr, sizeof(struct ipv4_pseudo_hdr) / 2); 
    checksum = calculate_checksum_continue(checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);  
    checksum = calculate_checksum_continue_flip(checksum, pkt->payload,     pkt->payload_len     / 2);

    if ((pkt->payload_len % 2) != 0) {
        uint16_t tmp = *(uint8_t *)(pkt->payload + pkt->payload_len - 1);

        checksum = calculate_checksum_finalize(checksum, &tmp, 1);
    } else {
        checksum = calculate_checksum_finalize(checksum, NULL, 0);
    }

	pet_printf("%u", checksum);
    return checksum;
}


uint16_t get_minimum(uint16_t x, uint16_t y){
    if(x < y)
        return x;
    return y;
}

int flag_handler(struct tcp_connection* con, struct tcp_raw_hdr* tcp_hdr){
    switch(con->con_state){
        case SYN_SENT:
            tcp_hdr->flags.SYN = 1;
            return 0;
        case SYN_RCVD:
            tcp_hdr->flags.SYN = 1;
            tcp_hdr->flags.ACK = 1;
            //con->seq_num_received++;
            return 0;
        case ESTABLISHED:
            tcp_hdr->flags.ACK = 1;
            return 0;
        case CLOSE_WAIT:
            tcp_hdr->flags.FIN = 1;
            tcp_hdr->flags.ACK = 1;
            return 0;
        case FIN_WAIT1:
            tcp_hdr->flags.FIN = 1;
            tcp_hdr->flags.ACK = 1;
            return 0;
        case FIN_WAIT2:
            //con->con_state = TIME_WAIT;
            tcp_hdr->flags.FIN = 1;
            tcp_hdr->flags.ACK = 1;
            return 0;
        case CLOSING:
           // con->con_state = TIME_WAIT;
            tcp_hdr->flags.FIN = 1;
            tcp_hdr->flags.ACK = 1;
            return 0;
        case TIME_WAIT:
            return -1;
        default:
            tcp_hdr->flags.ACK = 1;
            return 0; // change this return statement if the flag handler starts messing up
    }    
    return -1;
}

int send_pkt(struct tcp_connection * con){
    //pet_printf("sending packet");
    struct packet* pkt       = NULL;
    struct tcp_raw_hdr* tcp_hdr   = NULL;
    pkt = create_empty_packet();
    tcp_hdr = __make_tcp_hdr(pkt,1); //1 represents a single byte of options length
        tcp_hdr->src_port = htons(con->ipv4_tuple.local_port);
        tcp_hdr->dst_port = htons(con->ipv4_tuple.remote_port);
    if(flag_handler(con, tcp_hdr) == -1){
        pet_printf("Error setting flags correctly");
        exit(0);
    }
    tcp_hdr->seq_num = htonl(con->seq_num_local); //Make this random in the beginning
    tcp_hdr->ack_num = htonl(con->ack_num_local);
    tcp_hdr->header_len = pkt->layer_4_hdr_len;
    tcp_hdr->recv_win = htons((uint16_t) 1000);

    pkt->payload_len = get_minimum((uint16_t)pet_socket_send_capacity(con->sock),con->recv_win_received); //TODO: fix this
    //pet_printf("HERE HERE HERE %u \n",pkt->payload_len);
    pkt->payload     = pet_malloc(pkt->payload_len);
    //pkt->payload = NULL;
    //pkt->payload_len=0;
    //print_tcp_header(tcp_hdr);
    pet_socket_sending_data(con->sock, pkt->payload, pkt->payload_len);
    tcp_hdr->checksum = _calculate_checksum(con->ipv4_tuple.local_ip, con->ipv4_tuple.remote_ip, pkt);  
    //pet_printf("HERE HERE HERE %u \n",pkt->payload_len);  

    ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip);
        //pet_printf("I sent the packet.\n");
        //print_tcp_header(tcp_hdr);

    return 0;   
}



int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    
    struct tcp_connection* con = create_ipv4_tcp_con(tcp_state->con_map, local_addr, local_addr, local_port, local_port);
    
    add_sock_to_tcp_con(tcp_state->con_map,con,sock);
    con->con_state = LISTEN;
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
        struct tcp_connection* con = create_ipv4_tcp_con(tcp_state->con_map,local_addr,remote_addr,local_port,remote_port);
    add_sock_to_tcp_con(tcp_state->con_map,con,sock);
    con->con_state = SYN_SENT;
    send_pkt(con);
    put_and_unlock_tcp_con(con);
    return -1; /*TODO: Set con_state flag to SYN_SENT, call TCP_send with the connection, I will handle the outgoing packet in TCP_send
            create_ipv4_tcp_con, add_sock_to_tcp_con,
            lock the connection
            */
}

int 
tcp_passive_connect_ipv4(struct socket    * sock, 
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
        add_sock_to_tcp_con(tcp_state->con_map,con,sock);
        con->con_state = SYN_RCVD;
        put_and_unlock_tcp_con(con);
        return 0;
    }
    pet_printf("Port not listening. \n");
    return -1;
}


int
tcp_send(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con       = get_and_lock_tcp_con_from_sock(tcp_state->con_map,sock);

    if(con->con_state != ESTABLISHED){
        pet_printf("Connection is not established");
        return -1;
    }
    
    send_pkt(con);
    put_and_unlock_tcp_con(con);
    
    return 0;

    return -1;
}



/* Petnet assumes SO_LINGER semantics, so if we're here there is no pending write data */
int
tcp_close(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con       = get_and_lock_tcp_con_from_sock(tcp_state->con_map,sock);
    con->con_state = FIN_WAIT1;
    
    send_pkt(con);
    put_and_unlock_tcp_con(con);

    return 0;
}


/*int update_con_packet_info(struct tcp_connection * con, struct tcp_raw_hdr* tcp_hdr, struct packet* pkt){
        con->seq_num_received = ntohl(tcp_hdr->seq_num); //+ pkt->payload_len; I'm not sure if this goes here or not
        con->ack_num_received = ntohl(tcp_hdr->ack_num);
        //con->recv_win_received = ntohs(tcp_hdr->recv_win);

    return 0;   
}*/


int get_max(uint16_t x, uint16_t y ){
    if(x > y){
        return x;
    }
    return y;
}

void update_packet_numbers(struct tcp_connection * con, struct tcp_raw_hdr* tcp_hdr){
    con->seq_num_received = ntohl(tcp_hdr->seq_num); 
    con->ack_num_received = ntohl(tcp_hdr->ack_num);
    con->recv_win_received = ntohs(tcp_hdr->recv_win);
    return;
}

int stop_wait_receive(struct tcp_connection * con, struct tcp_raw_hdr* tcp_hdr, uint32_t payload_len){

    con->seq_num_received = ntohl(tcp_hdr->seq_num); 
    con->ack_num_received = ntohl(tcp_hdr->ack_num);
    con->recv_win_received = ntohs(tcp_hdr->recv_win);

    //we have not received any data yet
    if(con->ack_num_local == 0){
        con->ack_num_local = con->seq_num_received + payload_len;
        if(tcp_hdr->flags.SYN==1){
            con->ack_num_local++;
        }
    }
    //our Seq number keeps track of how much data weve sent
    con->seq_num_local = con->seq_num_local + payload_len;
    if(tcp_hdr->flags.SYN == 1){
        con->seq_num_local++;
    }

    //our Ack numbers confirm how much data weve received
    con->ack_num_local = con->ack_num_local + payload_len;
    if(tcp_hdr->flags.SYN == 1){
        con->ack_num_local++;
    }


    con->ack_num_local = con->seq_num_received + get_max(1, payload_len);
    
    pet_printf("All seems well here...\n");
    pet_printf("seq local: %u\n", con->seq_num_local);
    pet_printf("ack local: %u\n", con->ack_num_local);
    pet_printf("seq rec: %u\n", con->seq_num_received);
    pet_printf("ack rec: %u\n", con->ack_num_received);
    return 0;   
}

int
validate_packet(struct tcp_connection * con){
    if(con->seq_num_local > con->ack_num_received){
        return -1;
    }
    if(con->ack_num_local > con->seq_num_received){
        return -2;
    }
    return 0;
}

int 
tcp_pkt_rx(struct packet * pkt)
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

        if (petnet_state->debug_enable) {
            pet_printf("I received the packet.\n");
            print_tcp_header(tcp_hdr);

        }


        src_ip   = ipv4_addr_from_octets(ipv4_hdr->src_ip);
        dst_ip   = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
    /*if(ntohs(tcp_hdr->checksum) != _calculate_checksum(dst_ip, src_ip, pkt)){
        pet_printf("%u %u\n",tcp_hdr->checksum,_calculate_checksum(dst_ip, src_ip, pkt));
    return -1;          
    }*/
        if(tcp_hdr->flags.ACK != 1 && tcp_hdr->flags.SYN == 1){
            con_check_initial = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map,dst_ip,dst_ip,ntohs(tcp_hdr->dst_port),ntohs(tcp_hdr->dst_port)); //gotta free it
            if(con_check_initial == NULL || con_check_initial->con_state != LISTEN){
                pet_printf("Attempted to contact a server that was not listening");
                return -1;
            }
            put_and_unlock_tcp_con(con_check_initial); //free here is important b/c internal return statement.
            
            tcp_passive_connect_ipv4(con_check_initial->sock, dst_ip, ntohs(tcp_hdr->dst_port), src_ip, ntohs(tcp_hdr->src_port));
        } 

        con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, ntohs(tcp_hdr->dst_port), ntohs(tcp_hdr->src_port));
        if(con == NULL){ //Checks if con is not listening and there is no connection (effectively)
            return ret;
        }
        update_packet_numbers(con, tcp_hdr);
        int error = validate_packet(con);
        if(error < 0){
            pet_printf("wrong packet apparently");
        }
        switch(con->con_state){
            case SYN_RCVD:
                if(tcp_hdr->flags.ACK == 1){
                pet_printf("Handshake complete.\n");
                //Handshake complete, transition to data transfer state. No need to send another Ack here.
                    con->con_state = ESTABLISHED;
                    add_sock_to_tcp_con(tcp_state->con_map,con,pet_socket_accepted(con->sock, src_ip, ntohs(tcp_hdr->src_port)));  
                }else{   
                //We have to initalize seq and ack for our side of the communication
                //then we send it with the [SYN,ACK] flags
                con->ack_num_local = con->seq_num_received + 1; //increment for the SYN flag that we know we received
                con->seq_num_local = con->ack_num_received;                
                send_pkt(con);
                con->seq_num_local += 1; //increment our seq because we sent a syn too
                }
                break;

            case ESTABLISHED:
                if(tcp_hdr->flags.FIN == 1){
                    con->con_state = CLOSE_WAIT;
                }else if(tcp_hdr->flags.ACK == 1 && __get_payload_len(pkt) != 0){
                    pet_printf("Received data segment: %u bytes\n ", __get_payload_len(pkt));
                    con->ack_num_local += __get_payload_len(pkt);
                    send_pkt(con);
                }else if(tcp_hdr->flags.ACK == 1){
                    //pet_printf("Have not yet supported receiving acks in ESTABLISHED.");
                }
            break;

            case CLOSE_WAIT:
                if(tcp_hdr->flags.FIN == 1){
                    con->con_state = LAST_ACK;
                    send_pkt(con);
                }
                break;

            case LAST_ACK:
                if(tcp_hdr->flags.ACK == 1){
                    con->con_state = CLOSED;
                    pet_socket_closed(con->sock);
                    remove_tcp_con(tcp_state->con_map, con);
                    return ret;
                }
                break;

            case FIN_WAIT1:
                if(tcp_hdr->flags.ACK == 1){
                    con->con_state = FIN_WAIT2;
                }
                if(tcp_hdr->flags.FIN == 1){
                    con->con_state = CLOSED;
                //TODO: implement timeout?
                    pet_socket_closed(con->sock);
                    remove_tcp_con(tcp_state->con_map, con);
                    return ret;
                }
                break;

            case FIN_WAIT2:
                if(tcp_hdr->flags.FIN == 1){
                    con->con_state = CLOSED;
                //TODO: implement timeout?
                    pet_socket_closed(con->sock);
                    remove_tcp_con(tcp_state->con_map, con);
                    return ret;
                }
                break;
            default:
                break;
        }    
        put_and_unlock_tcp_con(con);
        pet_socket_received_data(con->sock,payload,pkt->payload_len); //TODO: Make sure that this isn't feeding too much data to the socket, Order may matter here and you may need to put this somewhere else. 
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
