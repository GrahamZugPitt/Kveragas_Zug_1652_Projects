/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#ifndef __PETNET_SOCKET_API_H__
#define __PETNET_SOCKET_API_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/select.h>
#include <sys/socket.h>
#include <poll.h>

extern int petnet_errno;
void petnet_perror(const char * s);

int petnet_socket(int domain, int type, int protocol);

int petnet_bind(int sockfd, const struct sockaddr * addr, socklen_t addr_len);

int petnet_listen(int sockfd, int backlog);

int petnet_accept(int sockfd, struct sockaddr * addr, socklen_t * addr_len);

int petnet_connect(int sockfd, struct sockaddr * addr, socklen_t addr_len);



ssize_t petnet_recv(int sockfd, void * buf, size_t count);
ssize_t petnet_send(int sockfd, void * buf, size_t count);

static inline ssize_t petnet_read (int fd, void * buf, size_t count) { return petnet_recv(fd, buf, count); }
static inline ssize_t petnet_write(int fd, void * buf, size_t count) { return petnet_send(fd, buf, count); }

ssize_t petnet_recvfrom(int sockfd, void * buf, size_t len, int flags,
                        struct sockaddr * src_addr, socklen_t * addr_len);

ssize_t petnet_sendto(int sockfd, void * buf, size_t len, int flags,
                      struct sockaddr * dst_addr, socklen_t addr_len);



int petnet_close(int fd);

//int petnet_poll(struct pollfd * fds, nfds_t nfds, int timeout);

int petnet_select(int              nfds, 
                  fd_set         * read_fds,
                  fd_set         * write_fds,
                  fd_set         * except_fds,
                  struct timeval * timeout);


#if 0
int petnet_set_nonblocking(int sockfd);
int petnet_set_blocking(int sockfd);
#endif


#ifdef __cplusplus
}
#endif

#endif