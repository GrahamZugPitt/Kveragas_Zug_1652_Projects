/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <petnet.h>


#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_util.h>
#include <petlib/pet_list.h>

#include "packet_pool.h"
#include "packet.h"
#include "arp.h"
#include "ethernet.h"
#include "timer.h"

#include <util/mac_address.h>
#include <util/ip_address.h>
#include <util/inet.h>

#define MAX_REQUEST_ATTEMPTS       5
#define REQUEST_RETRANS_DELAY_SECS 1
#define CACHE_ENTRY_LIFETIME_SECS  60

#define HTYPE_ETHER 0x0001
#define PTYPE_IPV4  0x0800

#define HLEN_ETHER 6
#define PLEN_IPV4  4

#define ARP_REQUEST 0x1
#define ARP_REPLY   0x2

struct arp_state {
	struct pet_hashtable * arp_cache;
//	struct pet_hashtable * rarp_cache;

	pthread_mutex_t arp_lock;
};

struct arp_cache_entry {
	int ref_cnt;
	pthread_mutex_t lock;

	struct ipv4_addr   * ip_addr;
	struct mac_addr    * mac_addr;
	struct pet_timeout * timeout;

	uint8_t num_requests;
	uint8_t pending;
	struct list_head pending_pkts;

};



void
__free_cache_entry(struct arp_cache_entry * entry)
{
	/* This will only be called after a timeout has expired, or before a timeout has been set. 
	 *  Therefore we do not need to cancel the timeout
     */
	if (entry->ip_addr)  free_ipv4_addr(entry->ip_addr);
	if (entry->mac_addr) free_mac_addr(entry->mac_addr);

 	{
		struct packet * pending_pkt = NULL;
		struct packet * tmp_pkt     = NULL;

		list_for_each_entry_safe(pending_pkt, tmp_pkt, &(entry->pending_pkts), list_node) {
			list_del(&(pending_pkt->list_node));
			free_packet(pending_pkt);
		}
 	}

	
	pet_free(entry);	
}

static inline void
__put_cache_entry(struct arp_cache_entry * entry)
{
	int ref_cnt = 0;

	ref_cnt = pet_atomic_dec(&(entry->ref_cnt));

	if (ref_cnt == 0) {
		__free_cache_entry(entry);
	}
}

static inline struct arp_cache_entry *
__get_cache_entry(struct arp_cache_entry * entry) {
	if (entry) pet_atomic_inc(&(entry->ref_cnt));
	return entry;
}

static uint32_t 
__arp_hash_fn(uintptr_t key)
{
	struct ipv4_addr * addr = (struct ipv4_addr *)key;
	uint32_t hash_key = 0;

	ipv4_addr_to_bytes(addr, (uint8_t *)&hash_key);

	return pet_hash_u32(hash_key);
}

static int
__arp_eq_fn(uintptr_t key1, 
			uintptr_t key2) 
{
	struct ipv4_addr * addr1 = (struct ipv4_addr *)key1;
	struct ipv4_addr * addr2 = (struct ipv4_addr *)key2;

	return (ipv4_addr_compare(addr1, addr2) == 0);
}

static int
__sanity_check_hdr(struct arp_raw_hdr * arp_hdr)
{
	if ((ntohs(arp_hdr->hw_type)        != HTYPE_ETHER) ||
		(ntohs(arp_hdr->proto_type)     != PTYPE_IPV4)  ||
		(arp_hdr->hw_addr_len           != HLEN_ETHER)  ||
		(arp_hdr->proto_addr_len        != PLEN_IPV4)) {
		log_error("Unhandled ARP Address types (HW_TYPE=0x%x) (HW_ADDR_LEN=%d) (PROTO_TYPE=0x%x) (PROTO_ADDR_LEN=%d)\n", 
				   ntohs(arp_hdr->hw_type), 
				   arp_hdr->hw_addr_len,
				   ntohs(arp_hdr->proto_type),
				   arp_hdr->proto_addr_len);
		return -1;
	}

	if ((ntohs(arp_hdr->opcode) != ARP_REQUEST) && 
		(ntohs(arp_hdr->opcode) != ARP_REPLY)) {
		log_error("Unhandled ARP opcode (%d)\n", ntohs(arp_hdr->opcode));
		return -1;
	}

	return 0;
}

static struct arp_raw_hdr *
__get_arp_hdr(struct packet * pkt)
{
	struct arp_raw_hdr * arp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len;

	pkt->layer_3_type    = ARP_PKT;
	pkt->layer_3_hdr     = arp_hdr;
	pkt->layer_3_hdr_len = sizeof(struct arp_raw_hdr);

	return arp_hdr;
}

static struct arp_raw_hdr *
__make_arp_hdr(struct packet * pkt)
{
	pkt->layer_3_type    = ARP_PKT;
	pkt->layer_3_hdr     = pet_malloc(sizeof(struct arp_raw_hdr));
	pkt->layer_3_hdr_len = sizeof(struct arp_raw_hdr);

	return (struct arp_raw_hdr*)(pkt->layer_3_hdr);
}

pet_json_obj_t
arp_hdr_to_json(struct arp_raw_hdr * hdr)
{
	pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;
	
	struct mac_addr  * src_mac = NULL;
	struct mac_addr  * tgt_mac = NULL;
	struct ipv4_addr * src_ip  = NULL;
	struct ipv4_addr * tgt_ip  = NULL;

	src_mac = mac_addr_from_octets(hdr->src_mac);
	tgt_mac = mac_addr_from_octets(hdr->tgt_mac);
	src_ip  = ipv4_addr_from_octets(hdr->src_ip);
	tgt_ip  = ipv4_addr_from_octets(hdr->tgt_ip);

	hdr_json = pet_json_new_obj("ARP Header");

	if (hdr_json == PET_JSON_INVALID_OBJ) {
		log_error("Could not create ARP Header JSON\n");
		goto err;
	}

	pet_json_add_u16(hdr_json, "hardware_type",     ntohs(hdr->hw_type));
	pet_json_add_u16(hdr_json, "protocol_type",     ntohs(hdr->proto_type));
	pet_json_add_u8 (hdr_json, "hardware_addr_len", hdr->hw_addr_len);
	pet_json_add_u8 (hdr_json, "protocol_addr_len", hdr->proto_addr_len);
	pet_json_add_u16(hdr_json, "opcode",            ntohs(hdr->opcode));
	
	ipv4_addr_to_json(src_ip, hdr_json, "src_ip");
	ipv4_addr_to_json(tgt_ip, hdr_json, "dst_ip");
	mac_addr_to_json(src_mac, hdr_json, "src_mac");
	mac_addr_to_json(tgt_mac, hdr_json, "dst_mac");


	free_mac_addr(src_mac);
	free_mac_addr(tgt_mac);
	free_ipv4_addr(src_ip);
	free_ipv4_addr(tgt_ip);

	return hdr_json;

err:

	if (src_mac) free_mac_addr(src_mac);
	if (tgt_mac) free_mac_addr(tgt_mac);
	if (src_ip)  free_ipv4_addr(src_ip);
	if (tgt_ip)  free_ipv4_addr(tgt_ip);

	return PET_JSON_INVALID_OBJ;

}

void
print_arp_hdr(struct arp_raw_hdr * arp_hdr)
{
	pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

	char * json_str = NULL;

	hdr_json = arp_hdr_to_json(arp_hdr);

	if (hdr_json == PET_JSON_INVALID_OBJ) {
		log_error("Could not serialize ARP Header to JSON\n");
		return;
	}

	json_str = pet_json_serialize(hdr_json);

	pet_printf("\"ARP Header\": %s\n", json_str);

	pet_free(json_str);
	pet_json_free(hdr_json);

	return;
}





static int
__send_arp_request(struct arp_cache_entry * cache_entry);



static struct arp_cache_entry * 
__arp_find_cache_entry(struct arp_state * arp_state, 
					   struct ipv4_addr * ip_addr)
{
	struct arp_cache_entry * cache_entry = NULL;

	pthread_mutex_lock(&(arp_state->arp_lock));
	{
		cache_entry = pet_htable_search(arp_state->arp_cache, (uintptr_t)ip_addr);
		cache_entry = __get_cache_entry(cache_entry);
	}
	pthread_mutex_unlock(&(arp_state->arp_lock));

	return cache_entry;
}


static struct arp_cache_entry * 
__arp_lookup_locked(struct ipv4_addr * ip_addr,
					int              * needs_request )
{
	struct arp_state       * arp_state = petnet_state->arp_state;
	struct arp_cache_entry * entry     = NULL;
	int ret = 0;

	entry = pet_htable_search(arp_state->arp_cache, (uintptr_t)ip_addr);

	if (entry == NULL) {
		entry = pet_malloc(sizeof(struct arp_cache_entry));

		entry->ref_cnt      = 1;
		entry->ip_addr      = ipv4_addr_clone(ip_addr);
		entry->mac_addr     = NULL;
		entry->timeout      = NULL;
		entry->pending      = 1;
		entry->num_requests = 0;

		pthread_mutex_init(&(entry->lock), NULL);
		INIT_LIST_HEAD(&(entry->pending_pkts));

	    if (petnet_state->debug_enable) {
			log_debug("Adding Pending entry to ARP cache\n");
		}

		ret = pet_htable_insert(arp_state->arp_cache, (uintptr_t)(entry->ip_addr), (uintptr_t)entry);

		if (ret == -1) {
			// We can't track it, so just nuke it
			__free_cache_entry(entry);
			return NULL;
		}

		// Caller is responsible for making request
		*needs_request = 1;
	}

	return __get_cache_entry(entry);
}


int
arp_lookup_and_tx(struct packet    * pkt, 
				  struct ipv4_addr * dst_addr)
{
	struct arp_state       * arp_state = petnet_state->arp_state;
	struct arp_cache_entry * entry     = NULL;

	int needs_request = 0;
	int can_send_pkt  = 0;
	int ret = 0;

	pthread_mutex_lock(&(arp_state->arp_lock));
	{
		entry = __arp_lookup_locked(dst_addr, &needs_request);
	}
	pthread_mutex_unlock(&(arp_state->arp_lock));

	if (entry == NULL) {
		log_error("Fatal ARP lookup\n");
		goto err;
	}

	pthread_mutex_lock(&(entry->lock));
	{
		if (entry->pending == 0) {
			can_send_pkt = 1;
		} else {
			list_add(&(pkt->list_node), &(entry->pending_pkts));
		}
	}
	pthread_mutex_unlock(&(entry->lock));

	if (can_send_pkt == 1) {
		ret = ethernet_pkt_tx(pkt, entry->mac_addr);

		if (ret == -1) {
			log_error("Failed to transmit packet\n");
			goto err;
		}

	} else if (needs_request == 1) {
		ret = __send_arp_request(entry);

		if (ret == -1) {
			log_error("Failed ARP lookup. Must abort packet transmit\n");
			goto err;
		}
	}

	__put_cache_entry(entry);

	return 0;
err:
	if (entry) __put_cache_entry(entry);

	return -1;
}

static void 
__request_timeout(struct pet_timeout * timeout, 
				  void               * arg)
{
	struct arp_state       * arp_state   = petnet_state->arp_state;
	struct arp_cache_entry * cache_entry = arg;

	log_debug("ARP Request timed out. Attempt %d.\n", cache_entry->num_requests);

	pthread_mutex_lock(&(cache_entry->lock));
	{
		cache_entry->timeout = NULL;
	}
	pthread_mutex_unlock(&(cache_entry->lock));

	if (cache_entry->num_requests == MAX_REQUEST_ATTEMPTS) {
		pthread_mutex_lock(&(arp_state->arp_lock));
		{
			pet_htable_remove(arp_state->arp_cache, (uintptr_t)(cache_entry->ip_addr));
			__put_cache_entry(cache_entry);
		}
		pthread_mutex_unlock(&(arp_state->arp_lock));
	} else {
		__send_arp_request(cache_entry);
	}

	__put_cache_entry(cache_entry);
	return;
}

static int
__send_arp_request(struct arp_cache_entry * cache_entry)
{
	struct packet      * request_pkt = NULL;
	struct arp_raw_hdr * request_hdr = NULL;

	struct mac_addr * dst_mac = mac_broadcast_addr();

	int ret = 0;

	request_pkt = create_empty_packet();

	if (request_pkt == NULL) {
		log_error("Failed to create ARP request packet\n");
		goto err;
	}

	request_hdr = __make_arp_hdr(request_pkt);

	request_hdr->hw_type        = htons(HTYPE_ETHER);
	request_hdr->proto_type     = htons(PTYPE_IPV4);
	request_hdr->hw_addr_len    = HLEN_ETHER;
	request_hdr->proto_addr_len = PLEN_IPV4;
	request_hdr->opcode         = htons(ARP_REQUEST);

	mac_addr_to_octets(petnet_state->mac_addr, request_hdr->src_mac);
	mac_addr_to_octets(dst_mac,                request_hdr->tgt_mac);
	ipv4_addr_to_octets(petnet_state->addr_v4, request_hdr->src_ip);
	ipv4_addr_to_octets(cache_entry->ip_addr,  request_hdr->tgt_ip);

    if (petnet_state->debug_enable) {
		log_debug("Sending ARP Request\n");
	}
	
	ret = ethernet_pkt_tx(request_pkt, dst_mac);

	if (ret == -1) {
		log_error("Failed to transmit ARP request\n");
		goto err;
	}

	pthread_mutex_lock(&(cache_entry->lock));
	{
		/* Check if we are still waiting for a reply */
		if (cache_entry->pending == 1) {
			cache_entry->num_requests += 1;
			cache_entry->timeout       = pet_add_timeout(REQUEST_RETRANS_DELAY_SECS, __request_timeout, __get_cache_entry(cache_entry));
		} 
	}
	pthread_mutex_unlock(&(cache_entry->lock));

	free_mac_addr(dst_mac);	

	return 0;

err:
	if (request_pkt) free_packet(request_pkt);
	if (dst_mac)     free_mac_addr(dst_mac);

	return -1;
}

static void 
__expiration_timeout(struct pet_timeout * timeout, 
				     void               * arg)
{
	struct arp_state       * arp_state   = petnet_state->arp_state;
	struct arp_cache_entry * cache_entry = arg;

	if (petnet_state->debug_enable) {
    	log_debug("Expiring ARP entry out of cache\n");
    }
    
	pthread_mutex_lock(&(arp_state->arp_lock));
	{
		pet_htable_remove(arp_state->arp_cache, (uintptr_t)(cache_entry->ip_addr));
		__put_cache_entry(cache_entry);
	}
	pthread_mutex_unlock(&(arp_state->arp_lock));

	__put_cache_entry(cache_entry);
	return;
}

static int
__handle_arp_reply(struct packet      * pkt,
				   struct arp_raw_hdr * hdr)
{
	struct arp_state       * arp_state   = petnet_state->arp_state;
	struct arp_cache_entry * cache_entry = NULL;
	struct ipv4_addr       * src_ip      = ipv4_addr_from_octets(hdr->src_ip);

	LIST_HEAD(pending_pkt_list);
    
	if (petnet_state->debug_enable) {
		log_debug("Received ARP Reply\n");
	}

	cache_entry = __arp_find_cache_entry(arp_state, src_ip);

	if (cache_entry == NULL) {
		/* Reply came too late, drop it */
		log_debug("Could not find cache entry for ARP reply\n");
		goto err;
	}

	pthread_mutex_lock(&(cache_entry->lock));
	{
		if (cache_entry->pending == 1) {
			if (cache_entry->timeout) {
				pet_cancel_timeout(cache_entry->timeout);
			}
			
			cache_entry->mac_addr = mac_addr_from_octets(hdr->src_mac);
			cache_entry->pending  = 0;
			cache_entry->timeout  = pet_add_timeout(CACHE_ENTRY_LIFETIME_SECS, __expiration_timeout, __get_cache_entry(cache_entry));
	
			list_splice_init(&(cache_entry->pending_pkts), &pending_pkt_list);
		}
	}
	pthread_mutex_unlock(&(cache_entry->lock));

	{
		struct packet * pending_pkt = NULL;
		struct packet * tmp_pkt     = NULL;

		list_for_each_entry_safe(pending_pkt, tmp_pkt, &pending_pkt_list, list_node) {
			list_del(&(pending_pkt->list_node));
			ethernet_pkt_tx(pending_pkt, cache_entry->mac_addr);
		}
	}

	free_ipv4_addr(src_ip);
	__put_cache_entry(cache_entry);
	
	return 0;

err:
	if (cache_entry) __put_cache_entry(cache_entry);
	if (src_ip)      free_ipv4_addr(src_ip);

	return -1;
}


static int
__handle_arp_request(struct packet      * pkt, 
					 struct arp_raw_hdr * hdr)
{
	struct ipv4_addr * src_ip  = ipv4_addr_from_octets(hdr->src_ip);
	struct ipv4_addr * tgt_ip  = ipv4_addr_from_octets(hdr->tgt_ip);
	struct mac_addr  * src_mac = mac_addr_from_octets(hdr->src_mac);

	struct packet      * reply_pkt = NULL;
	struct arp_raw_hdr * reply_hdr = NULL;

	int is_probe = 0;
	int ret = 0;


	if (ipv4_addr_is_nil(src_ip)) {
		is_probe = 1;
		(void)is_probe;
	} else {
		// cache the src info
	}



	if (ipv4_addr_compare(petnet_state->addr_v4, tgt_ip) != 0) {
		// Not our packet, drop it
		goto early_out;
	}


	/* Create ARP reply packet */
	reply_pkt = create_empty_packet();

	if (reply_pkt == NULL) {
		log_error("Failed to create ARP reply packet\n");
		goto err;
	}

	reply_hdr = __make_arp_hdr(reply_pkt);

	reply_hdr->hw_type        = htons(HTYPE_ETHER);
	reply_hdr->proto_type     = htons(PTYPE_IPV4);
	reply_hdr->hw_addr_len    = HLEN_ETHER;
	reply_hdr->proto_addr_len = PLEN_IPV4;
	reply_hdr->opcode         = htons(ARP_REPLY);

	mac_addr_to_octets(petnet_state->mac_addr, reply_hdr->src_mac);
	mac_addr_to_octets(src_mac,                reply_hdr->tgt_mac);
	ipv4_addr_to_octets(src_ip,                reply_hdr->tgt_ip);
	ipv4_addr_to_octets(tgt_ip,                reply_hdr->src_ip);


	/* Transmit Packet */

	ret = ethernet_pkt_tx(reply_pkt, src_mac);

	if (ret == -1) {
		log_error("Could not transmit ARP reply\n");
		goto err;
	}

early_out:
	free_ipv4_addr(src_ip);
	free_ipv4_addr(tgt_ip);
	free_mac_addr(src_mac);

	return 0;
err: 
	if (src_ip)     free_ipv4_addr(src_ip);
	if (tgt_ip) 	free_ipv4_addr(tgt_ip);
	if (src_mac)    free_mac_addr(src_mac);
	if (reply_pkt)  free_packet(reply_pkt);


	return -1;
}


int 
arp_pkt_rx(struct packet * pkt)

{
	struct arp_raw_hdr * arp_hdr  = __get_arp_hdr(pkt);
	int ret = 0;


	if (__sanity_check_hdr(arp_hdr) == -1) {
		log_error("Invalid ARP HDR\n");
		goto err;
	}

    if (petnet_state->debug_enable) {
		pet_printf("Received ARP Packet\n");
		print_arp_hdr(arp_hdr);
	}

	if (ntohs(arp_hdr->opcode) == ARP_REQUEST) {
		ret = __handle_arp_request(pkt, arp_hdr);

		if (ret == -1) {
			log_error("Failed to handle ARP request\n");
			goto err;
		}

	} else if (ntohs(arp_hdr->opcode) == ARP_REPLY) {
		ret = __handle_arp_reply(pkt, arp_hdr);

		if (ret == -1) {
			log_error("Failed to handle ARP Reply\n");
			goto err;
		}
	} else {
		log_error("Unhandled ARP opcode (%d)\n", arp_hdr->opcode);
		goto err;
	}


	return 0;

err:
	return -1;
}



int 
arp_init(struct petnet * petnet_state)
{
	struct arp_state * state = pet_malloc(sizeof(struct arp_state));

	if (state == NULL) {
		log_error("Failed to allocate ARP state\n");
		return -1;
	}

	state->arp_cache = pet_create_htable(0, __arp_hash_fn, __arp_eq_fn, NULL, NULL);

	pthread_mutex_init(&(state->arp_lock), NULL);

	petnet_state->arp_state = state;

	return 0;
}