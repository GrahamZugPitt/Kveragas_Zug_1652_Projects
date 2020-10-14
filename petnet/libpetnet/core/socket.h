/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __SOCKET_H__
#define __SOCKET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <petlib/pet_list.h>

typedef enum { PET_SOCK_TYPE_INVALID, 
               PET_SOCK_TYPE_UDP, 
               PET_SOCK_TYPE_TCP, 
               PET_SOCK_TYPE_ICMP } pet_sock_type_t;

typedef enum { PET_SOCK_FAMILY_INVALID, 
               PET_SOCK_FAMILY_IPV4, 
               PET_SOCK_FAMILY_IPV6 } pet_sock_family_t;

struct petnet;
struct ipv4_addr;

/*********************/
/* Utility Functions */
/*********************/

struct socket * 
pet_get_socket_from_fd(int fd);


/* 
 * Obtains a new reference to a socket 
 * 
 * Returns the pointer passed as an argument, this allows semantically clean assignment
 * e.g. 
 * some_persistent_obj->sock = pet_get_socket(sock);
 * 
 */
struct socket * 
pet_get_socket(struct socket * sock);

/* 
 * Releases a reference to a socket
 */
void
pet_put_socket(struct socket * sock);

/************************************/
/* Application Socket API Functions */
/************************************/

int pet_socket_create(pet_sock_family_t     family,
                      pet_sock_type_t       type);


int pet_socket_connect_ipv4(int sockfd, struct ipv4_addr * ip_addr, uint16_t port);



int pet_socket_bind(int sockfd, uint16_t port);

int pet_socket_listen(int sockfd, int backlog);

int pet_socket_accept_ipv4(int sockfd, struct ipv4_addr ** ipv4_addr, uint16_t * port);

ssize_t pet_socket_recv(int sockfd, void * buf, size_t count);
ssize_t pet_socket_send(int sockfd, void * buf, size_t count);


int 
pet_socket_recv_from(int               sockfd, 
                     void            * buf,
                     size_t            len,
                     struct sockaddr * src_addr,
                     socklen_t       * addr_len);

int 
pet_socket_send_to(int               sockfd, 
                   void            * buf,
                   size_t            len, 
                   struct sockaddr * src_addr,
                   socklen_t         addr_len);

int pet_socket_close(int sockfd);

int 
pet_socket_select(int              nfds, 
                  fd_set         * read_fds,
                  fd_set         * write_fds,
                  fd_set         * except_fds,
                  struct timeval * timeout);



/*******************************************************/
/* The following are up calls from the Transport layer */
/*******************************************************/

/* 
 * Notifies the socket layer when a connect() has completed successfully
 */
int
pet_socket_connected(struct socket * sock);


/* 
 * Notifies the socket layer when a new connection has been established as a result of an accept()
 */
struct socket * 
pet_socket_accepted(struct socket    * serv_sock,
                    struct ipv4_addr * remote_addr,
                    uint16_t           remote_port);


/* 
 * Notifies the socket layer that a socket has been closed 
 */
int
pet_socket_closed(struct socket * sock);

/*
 * Notifies the socket layer that an error has occured for a given socket 
 */
int
pet_socket_error(struct socket * sock, 
                 int             sock_errno);


/* 
 * Returns the available space in /sock/'s receive socket buffer 
 */
uint32_t 
pet_socket_recv_capacity(struct socket * sock);

/* 
 * Returns the amount of data waiting in /sock/'s outbound socket buffer 
 */
uint32_t 
pet_socket_send_capacity(struct socket * sock);


/* 
 * Passes stream data up to the socket layer after it has been received
 * 
 * Return value: 0 if /size/ bytes was successfully read from /buf/, -1 otherwise
 * 
 * Note that the socket buffer is statically sized, you must ensure that 
 * there is enough available space with pet_socket_recv_capacity()
 */
int 
pet_socket_received_data(struct socket * sock, 
                         void          * buf,
                         size_t          size);

/*
 * This pulls stream data from the socket layer to handle in the transport layer
 * /buf/ is a target buffer at least of size /size/ that will be written to
 * /size/ is the amount of data to write.
 * 
 *  Return value: 0 if /size/ bytes was successfully written to /buf/, -1 otherwise
 * 
 * Note that the socket buffer might not have available data from the application, 
 * you must ensure that available data with pet_socket_send_capacity()
 */
int 
pet_socket_sending_data(struct socket * sock, 
                        void          * buf,
                        size_t          size);


/* 
 * Passes a datagram up to the socket layer after it has been received 
 */
int
pet_socket_received_datagram(struct socket    * sock, 
                             void             * buf, 
                             size_t             size,
                             struct ipv4_addr * remote_addr,
                             uint16_t           remote_port);


/************************/
/* Global API functions */
/************************/

int socket_init(struct petnet * petnet_state);

#ifdef __cplusplus
}
#endif

#endif