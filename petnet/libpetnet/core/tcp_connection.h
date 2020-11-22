/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __TCP_CON_MAP_H__
#define __TCP_CON_MAP_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <pthread.h>

#include <util/ip_address.h>

struct socket;
struct tcp_con_map;



typedef enum { CLOSED      = 0,
               LISTEN      = 1,
               SYN_RCVD    = 2,
               SYN_SENT    = 3, 
               ESTABLISHED = 4,
               CLOSE_WAIT  = 5,
               FIN_WAIT1   = 6,
               CLOSING     = 7,
               LAST_ACK    = 8,
               FIN_WAIT2   = 9,
               TIME_WAIT   = 10} tcp_con_state_t;


struct tcp_con_ipv4_tuple {
    struct ipv4_addr * local_ip;
    struct ipv4_addr * remote_ip;
    uint16_t           local_port;
    uint16_t           remote_port;
};



struct tcp_connection {
    
    ip_net_type_t net_type;

    union {
        struct tcp_con_ipv4_tuple ipv4_tuple;
    };

    int ref_cnt;

    pthread_mutex_t con_lock;

    struct socket * sock;





    /* **********************
     * Students fill in below 
     * **********************/
    uint32_t seq_num_local; //These refer to the sequences numbers, etc. that we want the other machine to be on
    uint32_t ack_num_local; //THESE ARE STORED IN HOST BITS, IF YOU WRITE THEM TO THE NETWORK, YOU MUST CONVERT THEM FIRST
    uint16_t recv_win_local;

    uint32_t seq_num_received; //These refer to the sequences numbers, etc that we have gotten from the other machine
    uint32_t ack_num_received; //THESE ARE STORED IN HOST BITS, IF YOU WRITE THEM TO THE NETWORK, YOU MUST CONVERT THEM FIRST
    uint16_t recv_win_received;




    tcp_con_state_t con_state;


};


/*
 * Returns a locked reference to a TCP connection object corresponding to a socket 
 *   The pointer behaves like a normal pointer, but you cannot free it. 
 *   You must unlock and release the reference before returning
 * 
 * Returns NULL on error
 */
struct tcp_connection * 
get_and_lock_tcp_con_from_sock(struct tcp_con_map * map,
                               struct socket      * socket);

/*
 * Returns a locked reference to a TCP connection object corresponding to a IPV4 tuple 
 *   The pointer behaves like a normal pointer, but you cannot free it. 
 *   You must unlock and release the reference before returning
 * 
 * Returns NULL on error
 */
struct tcp_connection *
get_and_lock_tcp_con_from_ipv4(struct tcp_con_map * map,
                               struct ipv4_addr   * local_ip, 
                               struct ipv4_addr   * remote_ip,
                               uint16_t             local_port,
                               uint16_t             remote_port);

/* 
 * Unlocks and releases the reference to a tcp connection object after you are done using it
 */
void 
put_and_unlock_tcp_con(struct tcp_connection * con);


/* 
 * Creates a TCP connection object and returns a locked reference to it
 * 
 * NOTE: The object returned must be released with put_and_unlock_tcp_con() before returning
 * 
 *  Returns NULL on error
 */
struct tcp_connection *
create_ipv4_tcp_con(struct tcp_con_map * map,
                    struct ipv4_addr   * local_ip, 
                    struct ipv4_addr   * remote_ip,
                    uint16_t             local_port,
                    uint16_t             remote_port);


/* 
 * Associate a Socket with a TCP Connection
 *  This also allows searching for a TCP Connection object using its socket pointer 
 * 
 * Returns 0 on success, -1 on error
 */
int 
add_sock_to_tcp_con(struct tcp_con_map    * map,
                    struct tcp_connection * con, 
                    struct socket         * new_sock);



/* 
 *  Unregister a TCP Connection
 *   After this returns the TCP connection will no longer be accessible via the get_* functions
 */
void
remove_tcp_con(struct tcp_con_map    * map,
               struct tcp_connection * con);



/* 
 * Acquire a mutex lock on a TCP connection
 * 
 * Returns 0 on success, negative number on error
 */
int lock_tcp_con(struct tcp_connection * con);


/* 
 * Release a mutex lock on a TCP connection
 * 
 * Returns 0 on success, negative number on error
 */
int unlock_tcp_con(struct tcp_connection * con);


/* 
 * Obtains a new reference to a TCP connection 
 * 
 * Returns the pointer passed as an argument, this allows semantically clean assignment
 * 
 * e.g. 
 * some_persistent_obj->tcp_con = get_tcp_con(tcp_con);
 * 
 */
struct tcp_connection *
get_tcp_con(struct tcp_connection * con);

/*
 * Releases a reference to a TCP connection 
 */
void
put_tcp_con(struct tcp_connection * con);


/* 
 * Initializes a TCP Connection Map
 */
struct tcp_con_map * create_tcp_con_map();

#if 0

struct tcp_connection *
get_and_lock_tcp_con_from_ipv6(struct tcp_con_map * map,
                               struct ipv6_addr   * src_ip, 
                               struct ipv6_addr   * dst_ip,
                               uint16_t             src_port,
                               uint16_t             dst_port);

#endif

#ifdef __cplusplus
}
#endif

#endif
