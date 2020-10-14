/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#include <sys/socket.h>
#include <netinet/ip.h>
#include <errno.h>

#include <core/socket.h>

#include <util/ip_address.h>

#include <petlib/pet_log.h>
#include <petlib/pet_util.h>

#include "petnet_socket_api.h"


int petnet_errno;

int 
petnet_socket(int domain, 
              int type, 
              int protocol)
{
    pet_sock_family_t   sock_family = PET_SOCK_FAMILY_INVALID;
    pet_sock_type_t     sock_type   = PET_SOCK_TYPE_INVALID;

    switch(domain) {
        case AF_INET:
            sock_family = PET_SOCK_FAMILY_IPV4;
            break;
        case AF_INET6:
            sock_family = PET_SOCK_FAMILY_IPV6;
            break;
        default:
            log_error("Unsupported Socket Family\n");
            petnet_errno = EAFNOSUPPORT;
            goto err;
    }

    switch(type) {
        case SOCK_STREAM:
            sock_type = PET_SOCK_TYPE_TCP;
            break;
        case SOCK_DGRAM:
            sock_type = PET_SOCK_TYPE_UDP;
            break;
        default:
            log_error("Unsupported Socket Type\n");
            petnet_errno = EPROTONOSUPPORT;
            goto err;
    }


    return pet_socket_create(sock_family, sock_type);

err:
    return -1;

}


int 
petnet_connect(int               sockfd, 
               struct sockaddr * addr, 
               socklen_t         addr_len)
{
    int ret = 0;

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * saddr_in = (struct sockaddr_in *)addr;
        struct ipv4_addr   * ip_addr = ipv4_addr_from_octets((uint8_t *)&(saddr_in->sin_addr.s_addr));

        ret = pet_socket_connect_ipv4(sockfd, ip_addr, ntohs(saddr_in->sin_port));

        free_ipv4_addr(ip_addr);

        return ret;

    } else if (addr->sa_family == AF_INET6) {
        log_error("IPV6 not yet supported\n");
        petnet_errno = EAFNOSUPPORT;
        return -1;
    } else {
        petnet_errno = EAFNOSUPPORT;
        return -1;
    }
}

int 
petnet_bind(int                     sockfd, 
            const struct sockaddr * addr, 
            socklen_t               addr_len)
{
    int ret = 0;

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * saddr_in = (struct sockaddr_in *)addr;

        ret = pet_socket_bind(sockfd, ntohs(saddr_in->sin_port));

        return ret;
    } else if (addr->sa_family == AF_INET6) {
        log_error("IPV6 not yet supported\n");
        petnet_errno = EAFNOSUPPORT;
        return -1;
    } else {
        petnet_errno = EAFNOSUPPORT;
        return -1;
    }
}



int 
petnet_listen(int sockfd, 
              int backlog)
{
    return pet_socket_listen(sockfd, backlog);
}

int 
petnet_accept(int               sockfd, 
              struct sockaddr * addr, 
              socklen_t       * addr_len)
{

    int new_fd = -1;
    
    struct sockaddr_in * saddr_in    = (struct sockaddr_in *)addr;
    struct ipv4_addr   * remote_addr = NULL;
    uint16_t             remote_port = 0;
    

    new_fd = pet_socket_accept_ipv4(sockfd, &remote_addr, &remote_port);

    if (new_fd == -1) {
        return -1;
    }

    ipv4_addr_to_octets(remote_addr, (uint8_t *)&(saddr_in->sin_addr.s_addr));
    saddr_in->sin_port = htons(remote_port);


    return new_fd;

}



ssize_t
petnet_recv(int      sockfd,
            void   * buf, 
            size_t   count)
{
    return pet_socket_recv(sockfd, buf, count);
}


ssize_t
petnet_send(int      sockfd,
            void   * buf, 
            size_t   count)
{
    return pet_socket_send(sockfd, buf, count);
}


ssize_t 
petnet_recvfrom(int               sockfd, 
                void            * buf, 
                size_t            len, 
                int               flags,
                struct sockaddr * src_addr, 
                socklen_t       * addr_len)
{
    return pet_socket_recv_from(sockfd, buf, len, src_addr, addr_len);
}


ssize_t petnet_sendto(int                     sockfd, 
                      void                  * buf, 
                      size_t                  len, 
                      int                     flags,
                      struct sockaddr       * dst_addr,
                      socklen_t               addr_len)
{
    return pet_socket_send_to(sockfd, buf, len, dst_addr, addr_len);
}


int 
petnet_close(int fd)
{
    return pet_socket_close(fd);
}


int 
petnet_select(int              nfds, 
              fd_set         * read_fds,
              fd_set         * write_fds,
              fd_set         * except_fds,
              struct timeval * timeout)

{
    return pet_socket_select(nfds, read_fds, write_fds, except_fds, timeout);

}