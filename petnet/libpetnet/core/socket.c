/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <sys/time.h>

#include <petnet.h>


#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_ringbuffer.h>

#include <util/port_map.h>



#include "socket.h"
#include "tcp.h"
#include "udp.h"

#define SOCKET_BUFFER_SIZE (2 * 1024 * 1024)
#define MAX_SOCK_COUNT     (256)

extern struct petnet * petnet_state;
extern int             petnet_errno;

struct socket_state {
    struct socket * fd_table[MAX_SOCK_COUNT];

    struct port_map * tcp_port_map;
    struct port_map * udp_port_map;

    pthread_mutex_t lock;
    pthread_cond_t  poll_var;
};


struct socket;

struct socket {
    int fd;

    pet_sock_type_t   type;
    pet_sock_family_t family;

    struct {

        uint64_t connecting    : 1;
        uint64_t listening     : 1;


        uint64_t connected     : 1;
        uint64_t closed        : 1;

        uint64_t error         : 1;

    } __attribute__((packed));

    int sock_errno;

    struct pet_ringbuf * recv_buf;
    struct pet_ringbuf * send_buf;

    uint16_t local_port;
    uint16_t remote_port;

    union {
        struct ipv4_addr * local_addr_v4;
    };

    union {
        struct ipv4_addr * remote_addr_v4;
    };

    int              backlog;
    int              num_pending;
    struct list_head pending_list;


    pthread_mutex_t lock;
    pthread_cond_t  cond_var;

    int ref_cnt;
    struct list_head list_node;

};


struct ipv4_datagram_hdr {
    uint8_t  ip_addr[4];
    uint16_t port;
    uint16_t length;
} __attribute__((packed));


static void
__free_socket(struct socket * sock)
{


    if (sock) {

       // log_debug("FREEING SOCKET %p\n", sock);

        if (sock->recv_buf)   pet_free_ringbuf(sock->recv_buf);
        if (sock->send_buf)   pet_free_ringbuf(sock->send_buf);

        if (sock->family == PET_SOCK_FAMILY_IPV4) {
            if (sock->local_addr_v4)  free_ipv4_addr(sock->local_addr_v4);
        }


        if (sock->num_pending) {
            struct socket * pending = NULL;
            struct socket * tmp     = NULL;

            list_for_each_entry_safe(pending, tmp, &(sock->pending_list), list_node) {
                list_del(&(pending->list_node));
                pet_put_socket(pending);
            }
        }

        pthread_cond_destroy(&(sock->cond_var));
        pet_free(sock);
    }

    return;
}

struct socket * 
pet_get_socket(struct socket * sock)
{
    int ref_cnt = 0;
    ref_cnt = pet_atomic_inc(&(sock->ref_cnt));
    
    (void)ref_cnt;
    //  log_debug("GETTING Socket[sock=%p] (ref_cnt=%d)\n", sock, ref_cnt);


    return sock;
}


static struct socket * 
__get_socket_from_fd_locked(int fd)
{
    struct socket_state * sock_state = petnet_state->socket_state;
    struct socket       * sock       = NULL;


    sock = sock_state->fd_table[fd];

    if (sock) {
        pet_get_socket(sock);
    }

    return sock;
}


struct socket * 
pet_get_socket_from_fd(int fd)
{
    struct socket_state * sock_state = petnet_state->socket_state;
    struct socket       * sock       = NULL;

    pthread_mutex_lock(&(sock_state->lock));
    {
        sock = __get_socket_from_fd_locked(fd);
    }
    pthread_mutex_unlock(&(sock_state->lock));

    return sock;
}


void
pet_put_socket(struct socket * sock)
{
    struct socket_state * sock_state = petnet_state->socket_state;
    int ref_cnt = 0;

    ref_cnt = pet_atomic_dec(&(sock->ref_cnt));

    //  log_debug("PUTTING Socket [sock=%p] (ref_cnt=%d)\n", sock, ref_cnt);


    if (ref_cnt > 0) {
        return;        
    }


    /* If we're here, then this was the last reference, so we free the socket */

    pthread_mutex_lock(&(sock_state->lock));
    {
        if (sock->type == PET_SOCK_TYPE_TCP) {
            if (sock->local_port) port_map_release(sock_state->tcp_port_map, sock->local_port);
        } else if (sock->type == PET_SOCK_TYPE_UDP) {
            if (sock->local_port) port_map_release(sock_state->udp_port_map, sock->local_port);
        }
    }
    pthread_mutex_unlock(&(sock_state->lock));   

    __free_socket(sock);
}


static void
__remove_socket(struct socket * sock)
{
    struct socket_state * sock_state = petnet_state->socket_state;

    //  log_debug("REMOVING SOCKET %p (fd=%d)\n", sock, sock->fd);


    pthread_mutex_lock(&(sock_state->lock));
    {
        if (sock->fd != -1) {
            sock_state->fd_table[sock->fd] = NULL;
        }
    }
    pthread_mutex_unlock(&(sock_state->lock));

    pet_put_socket(sock);
}

static struct socket * 
__create_socket(pet_sock_family_t     family,
                pet_sock_type_t       type)
{
    struct socket_state * sock_state = petnet_state->socket_state;
    struct socket       * sock       = NULL;

    int ret = 0;

    sock = pet_malloc(sizeof(struct socket));

    sock->type        = type;
    sock->family      = family;
    sock->fd          = -1;
    sock->ref_cnt     = 1;
    sock->recv_buf    = pet_create_ringbuf(SOCKET_BUFFER_SIZE);
    sock->send_buf    = pet_create_ringbuf(SOCKET_BUFFER_SIZE);

    sock->local_port  = 0;
    sock->remote_port = 0;
    
    if (family == PET_SOCK_FAMILY_IPV4) {
        sock->local_addr_v4  = ipv4_addr_clone(petnet_state->addr_v4);
        sock->remote_addr_v4 = NULL;
    } else if (family == PET_SOCK_FAMILY_IPV6) {
        log_error("IPV6 not yet supported\n");
        goto err;
    }

    ret |= pthread_cond_init(&(sock->cond_var), NULL);
    ret |= pthread_mutex_init(&(sock->lock), NULL);


    sock->backlog     = 0;
    sock->num_pending = 0;
    INIT_LIST_HEAD(&(sock->pending_list));

    if ( (ret            != 0   ) ||
         (sock->recv_buf == NULL) ||
         (sock->send_buf == NULL) ) {
        log_error("Could not initialize pthread structures\n");
        goto err;
    }

    /* Find available FD */
    pthread_mutex_lock(&(sock_state->lock));
    {
        int i = 0;

        for (i = 0; i < MAX_SOCK_COUNT; i++)  {
            if (sock_state->fd_table[i] == NULL) {
                sock_state->fd_table[i] = sock;
                sock->fd                = i;
                break;
            }
        }

    }
    pthread_mutex_unlock(&(sock_state->lock));



    if (sock->fd == -1) {
        log_error("Could not find available file descriptor for socket\n");
        goto err;
    }

    return sock;

err:

    __free_socket(sock);

    return NULL;
}

/***********************************************/
/* Application Socket API Functions Start Here */
/***********************************************/



int 
pet_socket_create(pet_sock_family_t     family,
                  pet_sock_type_t       type)
{
    struct socket * sock = NULL;

    sock = __create_socket(family, type);

    if (sock == NULL) {
        petnet_errno = EIO;
        goto err;
    }

    return sock->fd;
err:

    return -1;    
}   





int 
pet_socket_bind(int      sockfd, 
                uint16_t port)
{
    struct socket_state * sock_state = petnet_state->socket_state;
    struct socket       * sock       = pet_get_socket_from_fd(sockfd);

    if (sock == NULL) {
        petnet_errno = EBADF;
        goto err;
    }

    if (sock->local_port != 0) {
        petnet_errno = EINVAL;
        goto err;
    }

    pthread_mutex_lock(&(sock_state->lock));
    {
        if (sock->type == PET_SOCK_TYPE_TCP) {
            sock->local_port = port_map_alloc(sock_state->tcp_port_map, port);
        } else if (sock->type == PET_SOCK_TYPE_UDP) {
            sock->local_port = port_map_alloc(sock_state->udp_port_map, port);
        }
    }
    pthread_mutex_unlock(&(sock_state->lock));

    if (sock->local_port == 0) {
        petnet_errno = EADDRINUSE;
        goto err;
    }

    if (sock->type == PET_SOCK_TYPE_UDP) {
        udp_bind(sock, petnet_state->addr_v4, sock->local_port);
    }

    pet_put_socket(sock);

    return 0;
err:
    if (sock) pet_put_socket(sock);
    return -1;
}

int 
pet_socket_listen(int sockfd, 
                  int backlog)
{
    struct socket * sock = pet_get_socket_from_fd(sockfd);  
    int ret = 0;

    if (sock == NULL) {
        petnet_errno = EBADF;
        goto err;
    }

    sock->backlog       = backlog;
    sock->num_pending   = 0;
    sock->listening     = 1;

    if (sock->type != PET_SOCK_TYPE_TCP) {
        petnet_errno = EOPNOTSUPP;
        goto err;
    }

    ret = tcp_listen(sock, sock->local_addr_v4, sock->local_port);

    if (ret != 0) {
        petnet_errno = EADDRINUSE;
        goto err;
    }

    
    pet_put_socket(sock);

    return 0;
err:
    if (sock) pet_put_socket(sock);
    return -1;
}


static int
__pet_socket_accept_ipv4(struct socket     * sock, 
                         struct ipv4_addr ** remote_addr, 
                         uint16_t          * remote_port)
{
    struct socket * new_sock = NULL;
    int fd = 0;

    while ((sock->num_pending == 0) &&
           (sock->error       == 0)) {
        pthread_cond_wait(&(sock->cond_var), &(sock->lock));
    }

    if (sock->error == 1) {
        petnet_errno = sock->sock_errno;
        goto err;
    }

    new_sock = list_first_entry(&(sock->pending_list), struct socket, list_node);

    if (new_sock == NULL) {
        goto err;
    }

    list_del(&(new_sock->list_node));
    sock->num_pending--;


    fd = new_sock->fd;
    *remote_addr = ipv4_addr_clone(new_sock->remote_addr_v4);
    *remote_port = new_sock->remote_port;

    pet_put_socket(new_sock);

    return fd;
err:
    if (new_sock) pet_put_socket(new_sock);
    return -1;
}

int 
pet_socket_accept_ipv4(int                 sockfd, 
                       struct ipv4_addr ** remote_addr, 
                       uint16_t          * remote_port)
{
    struct socket * sock     = pet_get_socket_from_fd(sockfd);
    int ret = 0;

    if (sock == NULL) {
        petnet_errno = EBADF;
        goto err;
    }

    if (sock->type != PET_SOCK_TYPE_TCP) {
        petnet_errno = EOPNOTSUPP;
        goto err;
    }

    if (sock->listening == 0) {
        petnet_errno = EINVAL;
        goto err;
    }

    pthread_mutex_lock(&(sock->lock));
    {
        ret = __pet_socket_accept_ipv4(sock, remote_addr, remote_port);
    }
    pthread_mutex_unlock(&(sock->lock));

    pet_put_socket(sock);

    return ret;
err:

    if (sock) pet_put_socket(sock);
    return -1;
}

int 
pet_socket_connect_ipv4(int                sockfd, 
                        struct ipv4_addr * dst_addr, 
                        uint16_t           dst_port)
{
    struct socket_state * sock_state = petnet_state->socket_state;
    struct socket       * sock       = pet_get_socket_from_fd(sockfd);

    int ret = 0;

    if (sock == NULL) {
        petnet_errno = EBADF;
        goto err;
    }

    if (sock->family != PET_SOCK_FAMILY_IPV4) {
        petnet_errno = EAFNOSUPPORT;
        goto err;
    }

    if (sock->connected == 1) {
        petnet_errno = EISCONN;
        goto err;
    }

    if (sock->connecting == 1) {
        petnet_errno = EALREADY;
        goto err;
    }

    if (sock->type != PET_SOCK_TYPE_TCP) {
        petnet_errno = EPROTOTYPE;
        goto err;
    }

    sock->connecting = 1;

    sock->remote_addr_v4 = ipv4_addr_clone(dst_addr);
    sock->remote_port    = dst_port;

    if (sock->local_port == 0) {
        pthread_mutex_lock(&(sock_state->lock));
        {
            sock->local_port = port_map_alloc(sock_state->tcp_port_map, 0);
        }
        pthread_mutex_unlock(&(sock_state->lock));
    }

    ret = tcp_connect_ipv4(sock,
                           sock->local_addr_v4, 
                           sock->local_port, 
                           sock->remote_addr_v4, 
                           sock->remote_port);

    if (ret == -1) {
        petnet_errno = ENETUNREACH;
        goto err;
    }

    pthread_mutex_lock(&(sock->lock));
    {
        while ((sock->connected == 0) &&
               (sock->error     == 0)) {
            pthread_cond_wait(&(sock->cond_var), &(sock->lock));
        }

    }
    pthread_mutex_unlock(&(sock->lock));

    if (sock->error == 1) {
        petnet_errno = sock->sock_errno;
        goto err;
    }

    pet_put_socket(sock);

    return 0;
err:
    if (sock) pet_put_socket(sock);

    return -1;

}

static ssize_t
__pet_socket_recv(struct socket * sock, 
                  void          * buf,
                  size_t          count)
{
    size_t avail_bytes   = 0; 
    size_t bytes_to_read = 0;
    size_t bytes_read    = 0;

    while ( (pet_ringbuf_is_empty(sock->recv_buf)) &&
            (sock->error  == 0) &&
            (sock->closed == 0) ) {
        pthread_cond_wait(&(sock->cond_var), &(sock->lock));
    }

    if (sock->error == 1) {
        petnet_errno = sock->sock_errno;
        return -1;
    }

    if (sock->closed == 1) {
        return 0;
    }


    avail_bytes   = pet_ringbuf_used_space(sock->recv_buf);
    bytes_to_read = (count < avail_bytes) ? count : avail_bytes;

    bytes_read = pet_ringbuf_read(sock->recv_buf, buf, bytes_to_read);

    return bytes_read;
}

ssize_t
pet_socket_recv(int    sockfd, 
                void * buf,
                size_t count)
{
    struct socket * sock = pet_get_socket_from_fd(sockfd);
    size_t bytes_read = 0; 

    if (sock == NULL) {
        petnet_errno = EBADF;
        return -1;
    }


    pthread_mutex_lock(&(sock->lock));
    {
        bytes_read = __pet_socket_recv(sock, buf, count);
    }
    pthread_mutex_unlock(&(sock->lock));

    pet_put_socket(sock);

    return bytes_read;
}


static ssize_t
__pet_socket_send(struct socket * sock, 
                  void          * buf,
                  size_t          count)
{
    size_t avail_bytes   = 0; 
    size_t bytes_to_send = 0;
    size_t bytes_sent    = 0;


    while ( (pet_ringbuf_is_full(sock->send_buf)) &&
            (sock->error == 0) ) {
        pthread_cond_wait(&(sock->cond_var), &(sock->lock));
    }

    if (sock->error == 1) {
        petnet_errno = sock->sock_errno;
        return -1;
    }

    avail_bytes   = pet_ringbuf_free_space(sock->send_buf);
    bytes_to_send = (count < avail_bytes) ? count : avail_bytes;

    bytes_sent = pet_ringbuf_write(sock->send_buf, buf, bytes_to_send);

    return bytes_sent;
}

ssize_t
pet_socket_send(int    sockfd, 
                void * buf,
                size_t count)
{
    struct socket * sock = pet_get_socket_from_fd(sockfd);
    size_t bytes_sent = 0; 
    int ret = 0;
    
    if (sock == NULL) {
        petnet_errno = EBADF;
        return -1;
    }

    while (bytes_sent != count) {
        pthread_mutex_lock(&(sock->lock));
        {
            ret = __pet_socket_send(sock, buf + bytes_sent, count - bytes_sent);
        }
        pthread_mutex_unlock(&(sock->lock));

        if (ret == -1) {
            break;
        }

        bytes_sent += ret;

        tcp_send(sock);
    }

    pet_put_socket(sock);

    if (ret == -1) {
        return -1;
    } else {
        return bytes_sent;
    }
}

static int 
__pet_socket_recv_from(struct socket   * sock,
                       void            * buf,
                       size_t            len,
                       struct sockaddr * src_addr,
                       socklen_t       * src_addr_len)
{
    struct ipv4_datagram_hdr hdr;
    struct sockaddr_in       saddr_v4;

    int read_len = 0;
    int addr_len = 0;

    memset(&hdr,      0, sizeof(struct ipv4_datagram_hdr));
    memset(&saddr_v4, 0, sizeof(struct sockaddr_in));

    while ( (pet_ringbuf_is_empty(sock->recv_buf)) &&
            (sock->error == 0) ) {
        pthread_cond_wait(&(sock->cond_var), &(sock->lock));
    }

    if (sock->error == 1) {
        petnet_errno = sock->sock_errno;
        return -1;
    }

    pet_ringbuf_read(sock->recv_buf, &hdr, sizeof(struct ipv4_datagram_hdr));

    read_len = (hdr.length > len) ? len : hdr.length;

    pet_ringbuf_read(sock->recv_buf, buf, read_len);
    pet_ringbuf_read(sock->recv_buf, NULL, hdr.length - read_len); // Drain the rest of the datagram

    saddr_v4.sin_family      = AF_INET;
    saddr_v4.sin_addr.s_addr = htonl(*(uint32_t *)(hdr.ip_addr));
    saddr_v4.sin_port        = htons(hdr.port);

    addr_len = (*src_addr_len > sizeof(struct sockaddr_in)) ? sizeof(struct sockaddr_in) : *src_addr_len;

    memcpy(src_addr, &saddr_v4, addr_len);
    *src_addr_len = sizeof(struct sockaddr_in);

    return read_len;
}


int 
pet_socket_recv_from(int               sockfd, 
                     void            * buf,
                     size_t            len,
                     struct sockaddr * src_addr,
                     socklen_t       * addr_len)
{
    struct socket * sock = pet_get_socket_from_fd(sockfd);
    size_t bytes_read = 0;

    if (sock == NULL) {
        petnet_errno = EBADF;
        return -1;
    }

    pthread_mutex_lock(&(sock->lock));
    {
        bytes_read = __pet_socket_recv_from(sock, buf, len, src_addr, addr_len);
    }
    pthread_mutex_unlock(&(sock->lock));

    pet_put_socket(sock);

    return bytes_read;
}


int 
pet_socket_send_to(int               sockfd, 
                   void            * buf,
                   size_t            len, 
                   struct sockaddr * dst_addr,
                   socklen_t         addr_len)
{
    struct socket       * sock       = pet_get_socket_from_fd(sockfd);
    struct sockaddr_in  * daddr_v4   = (struct sockaddr_in *)dst_addr;
    struct ipv4_addr    * dst_ip     = ipv4_addr_from_octets((uint8_t *)&(daddr_v4->sin_addr.s_addr));

    size_t bytes_sent = 0;
    
    if (sock == NULL) {
        petnet_errno = EBADF;
        return -1;
    }

    if (sock->local_port == 0) {
        log_error("Binding anonymous port\n");
        pet_socket_bind(sockfd, 0);
    }


    bytes_sent = udp_send_datagram(sock, buf, len, dst_ip, ntohs(daddr_v4->sin_port));

    return bytes_sent;
}


int
pet_socket_close(int sockfd)
{
    struct socket * sock = pet_get_socket_from_fd(sockfd);
    int ret = 0;

    if (sock == NULL) {
        petnet_errno = -EBADF;
        goto err;
    }

    pthread_mutex_lock(&(sock->lock));
    {
        /* We have built-in SO-LINGER semantics */
        while ( (!pet_ringbuf_is_empty(sock->send_buf)) &&
                (sock->error == 0)) {
            pthread_cond_wait(&(sock->cond_var), &(sock->lock));
        }
    }
    pthread_mutex_unlock(&(sock->lock));

    if (sock->error == 1) {
        petnet_errno = sock->sock_errno;
        goto err;
    }

    sock->closed = 1;

    if (sock->type == PET_SOCK_TYPE_TCP) {
        ret = tcp_close(sock);
    } else if (sock->type == PET_SOCK_TYPE_UDP) {
        ret = udp_close(sock);
    }

    if (ret != 0) {
        petnet_errno = -EIO;
        goto err;
    }

    __remove_socket(sock);
    pet_put_socket(sock);

    return 0;

err:
    if (sock) pet_put_socket(sock);

    return -1;
}


static int
__timeval_to_abs_timespec(struct timeval  * tval,
                          struct timespec * tspec)
{
    struct timespec tmp_tspec;
    int ret = 0;



    ret = clock_gettime(CLOCK_REALTIME, tspec);

    if (ret != 0) {
        log_error("Failed to get current system time\n");
        return -1;
    }

    TIMEVAL_TO_TIMESPEC(tval, &tmp_tspec);

    tspec->tv_sec  += tmp_tspec.tv_sec;
    tspec->tv_nsec += tmp_tspec.tv_nsec;

    if (tspec->tv_nsec  > 1000000000) {
        tspec->tv_nsec -= 1000000000;
        tspec->tv_sec  += 1;
    }

    return 0;

}




static int 
__socket_select_2(int              nfds, 
                  fd_set         * read_fds,
                  fd_set         * write_fds,
                  fd_set         * except_fds) 
{
    fd_set tmp_read_fds;
    fd_set tmp_write_fds;
    fd_set tmp_except_fds;

    
    FD_ZERO(&tmp_read_fds);
    FD_ZERO(&tmp_write_fds);
    FD_ZERO(&tmp_except_fds);


    int ret = 0;
    int i = 0;



    /* We'll do this slow and simple */
    for (i = 0; i < nfds; i++) {
        if ( ((read_fds   != NULL) && (FD_ISSET(i, read_fds  ))) ||
             ((write_fds  != NULL) && (FD_ISSET(i, write_fds ))) ||
             ((except_fds != NULL) && (FD_ISSET(i, except_fds))) ) {
           
            struct socket * sock = __get_socket_from_fd_locked(i);
            
            if (sock == NULL) {
                petnet_errno = EBADF;
                return -1;
            }


            pthread_mutex_lock(&(sock->lock));
            {
                if ((read_fds != NULL) &&
                    (FD_ISSET(i, read_fds))) {

                    if ((sock->listening   == 1) && 
                        (sock->num_pending  > 0)) {
                        FD_SET(i, &tmp_read_fds);
                        ret++;  
                    } else if ((sock->listening == 0) && 
                               (!pet_ringbuf_is_empty(sock->recv_buf))) {
                        FD_SET(i, &tmp_read_fds);
                        ret++;
                    } else if (sock->closed == 1) {
                        FD_SET(i, &tmp_read_fds);
                        ret++;
                    }
                }

                if ((write_fds != NULL)  && 
                    (FD_ISSET(i, write_fds))) {
                    
                    if (!pet_ringbuf_is_full(sock->send_buf)) {
                        FD_SET(i, &tmp_write_fds);
                        ret++;
                    }
                }

                if ((except_fds != NULL) && 
                    (FD_ISSET(i, except_fds))) {

                    if (sock->error == 1) {
                        FD_SET(i, &tmp_except_fds);
                        ret++;
                    }
                }
            }
            pthread_mutex_unlock(&(sock->lock));

            pet_put_socket(sock);
        }
    }

    if (read_fds   != NULL) *read_fds   = tmp_read_fds;
    if (write_fds  != NULL) *write_fds  = tmp_write_fds;
    if (except_fds != NULL) *except_fds = tmp_except_fds;

    return ret;
}

static int 
__socket_select_1(int              nfds, 
                  fd_set         * read_fds,
                  fd_set         * write_fds,
                  fd_set         * except_fds,
                  struct timeval * timeout)
{
    struct socket_state * sock_state = petnet_state->socket_state;

    fd_set cached_read_fds;
    fd_set cached_write_fds;
    fd_set cached_except_fds;

    int ret = 0;

    if (read_fds   != NULL) cached_read_fds   = *read_fds;
    if (write_fds  != NULL) cached_write_fds  = *write_fds;
    if (except_fds != NULL) cached_except_fds = *except_fds;

    ret = __socket_select_2(nfds, read_fds, write_fds, except_fds);
    
 
    if (ret > 0) {
        return ret;
    }
 
    if (timeout) {
        struct timespec timeout_ts;

        __timeval_to_abs_timespec(timeout, &timeout_ts);
 
         ret = pthread_cond_timedwait(&(sock_state->poll_var), &(sock_state->lock), &timeout_ts);

        if (ret == ETIMEDOUT) {
            return 0;
        }
    } else {
        pthread_cond_wait(&(sock_state->poll_var), &(sock_state->lock));
    }

    if (read_fds   != NULL) *read_fds   = cached_read_fds;
    if (write_fds  != NULL) *write_fds  = cached_write_fds;
    if (except_fds != NULL) *except_fds = cached_except_fds;

    return __socket_select_2(nfds, read_fds, write_fds, except_fds);
}


int 
pet_socket_select(int              nfds, 
                  fd_set         * read_fds,
                  fd_set         * write_fds,
                  fd_set         * except_fds,
                  struct timeval * timeout)
{
    struct socket_state * sock_state = petnet_state->socket_state;

    int ret = 0;


    pthread_mutex_lock(&(sock_state->lock));
    {
        ret = __socket_select_1(nfds, read_fds, write_fds, except_fds, timeout);
    }
    pthread_mutex_unlock(&(sock_state->lock));

    return ret;
}



/*******************************************************/
/* The following are up calls from the Transport layer */
/*******************************************************/



int
pet_socket_connected(struct socket * sock)
{
    pthread_mutex_lock(&(sock->lock));
    {
        sock->connected  = 1;
        pthread_cond_signal(&(sock->cond_var));
    }
    pthread_mutex_unlock(&(sock->lock));

    return 0;
}


int
pet_socket_closed(struct socket * sock)
{
    struct socket_state * sock_state = petnet_state->socket_state; 

    pthread_mutex_lock(&(sock->lock));
    {
        sock->closed = 1;
        pthread_cond_signal(&(sock->cond_var));
    }
    pthread_mutex_unlock(&(sock->lock));

    pthread_mutex_lock(&(sock_state->lock));
    {
        pthread_cond_signal(&(sock_state->poll_var));
    }
    pthread_mutex_unlock(&(sock_state->lock));

    return 0;
}


static struct socket *
__pet_sock_accepted_ipv4(struct socket    * serv_sock, 
                         struct ipv4_addr * remote_addr,
                         uint16_t           remote_port)
{
    struct socket * new_sock = NULL;    

    if (serv_sock->listening == 0) {
        log_error("Cannot accept on a non-listening socket\n");
        goto err;
    }


    if (serv_sock->num_pending == serv_sock->backlog) {
        log_error("Reached backlog limit\n");
        goto err;
    }


    new_sock = __create_socket(serv_sock->family, serv_sock->type);

    new_sock->remote_addr_v4 = ipv4_addr_clone(remote_addr);
    new_sock->remote_port    = remote_port;
    new_sock->local_port     = serv_sock->local_port;


    serv_sock->num_pending++;
    list_add_tail(&(new_sock->list_node), &(serv_sock->pending_list));

    pthread_cond_signal(&(serv_sock->cond_var));

    return pet_get_socket(new_sock);

err:
    if (new_sock) __free_socket(new_sock);
    
    return NULL;
}

struct socket * 
pet_socket_accepted(struct socket    * serv_sock,
                    struct ipv4_addr * remote_addr,
                    uint16_t           remote_port)
{
    struct socket_state * sock_state = petnet_state->socket_state;   
    struct socket       * new_sock   = NULL;

    pthread_mutex_lock(&(serv_sock->lock));
    {
        new_sock = __pet_sock_accepted_ipv4(serv_sock, remote_addr, remote_port);
    }
    pthread_mutex_unlock(&(serv_sock->lock));

    pthread_mutex_lock(&(sock_state->lock));
    {
        pthread_cond_signal(&(sock_state->poll_var));
    }
    pthread_mutex_unlock(&(sock_state->lock));

    return new_sock;
}

int
pet_socket_error(struct socket * sock, 
                 int             sock_errno)
{
    struct socket_state * sock_state = petnet_state->socket_state;   

    pthread_mutex_lock(&(sock->lock));
    {
        sock->error      = 1;
        sock->sock_errno = sock_errno;

        pthread_cond_signal(&(sock->cond_var));
    }
    pthread_mutex_unlock(&(sock->lock));

    pthread_mutex_lock(&(sock_state->lock));
    {
        pthread_cond_signal(&(sock_state->poll_var));
    }
    pthread_mutex_unlock(&(sock_state->lock));


    return 0;
}



int
pet_socket_received_datagram(struct socket    * sock, 
                             void             * buf, 
                             size_t             size,
                             struct ipv4_addr * remote_addr,
                             uint16_t           remote_port)
{
    struct socket_state * sock_state = petnet_state->socket_state;   
    struct ipv4_datagram_hdr hdr;
    int dropped = 0;

    memset(&hdr, 0, sizeof(struct ipv4_datagram_hdr));

    ipv4_addr_to_bytes(remote_addr, hdr.ip_addr);
    hdr.port   = remote_port;
    hdr.length = size;

    pthread_mutex_lock(&(sock->lock));
    {
        if (pet_ringbuf_free_space(sock->recv_buf) >= (size + sizeof(struct ipv4_datagram_hdr))) {
            pet_ringbuf_write(sock->recv_buf, &hdr, sizeof(struct ipv4_datagram_hdr));
            pet_ringbuf_write(sock->recv_buf, buf,  size);
            pthread_cond_signal(&(sock->cond_var));
        } else {
            dropped = 1;
        }
    }
    pthread_mutex_unlock(&(sock->lock));

    if (dropped == 1) {
        return -1;
    }

    pthread_mutex_lock(&(sock_state->lock));
    {
        pthread_cond_signal(&(sock_state->poll_var));
    }
    pthread_mutex_unlock(&(sock_state->lock));

    return 0;
}

int 
pet_socket_received_data(struct socket * sock, 
                        void          * buf,
                        size_t          size)
{
    struct socket_state * sock_state = petnet_state->socket_state;   
    size_t bytes_wrote = 0;

    pthread_mutex_lock(&(sock->lock));
    {
        bytes_wrote = pet_ringbuf_write(sock->recv_buf, buf, size);
        pthread_cond_signal(&(sock->cond_var));
    }
    pthread_mutex_unlock(&(sock->lock));

    pthread_mutex_lock(&(sock_state->lock));
    {
        pthread_cond_signal(&(sock_state->poll_var));
    }
    pthread_mutex_unlock(&(sock_state->lock));


    if (bytes_wrote != size) {
        log_error("Socket receive buffer was too small to handle data\n");
        log_error("This should never happen, and some of the data was lost\n");
        return -1;
    }

    return 0;
}

int 
pet_socket_sending_data(struct socket * sock, 
                        void          * buf,
                        size_t          size)
{
    struct socket_state * sock_state = petnet_state->socket_state;   
    size_t bytes_read = 0;

    pthread_mutex_lock(&(sock->lock));
    {
        bytes_read = pet_ringbuf_read(sock->send_buf, buf, size);
        pthread_cond_signal(&(sock->cond_var));
    }
    pthread_mutex_unlock(&(sock->lock));


    pthread_mutex_lock(&(sock_state->lock));
    {
        pthread_cond_signal(&(sock_state->poll_var));
    }
    pthread_mutex_unlock(&(sock_state->lock));

    

    if (bytes_read != size) {
        log_error("Socket send buffer was too small to provide enough data\n");
        log_error("This should never happen, and some of the destination buffer is undefined\n");
        return -1;      
    }

    return 0;
}

uint32_t 
pet_socket_recv_capacity(struct socket * sock)
{
    size_t capacity = 0;

    pthread_mutex_lock(&(sock->lock));
    {
        capacity = pet_ringbuf_free_space(sock->recv_buf);
    }
    pthread_mutex_unlock(&(sock->lock));

    return capacity;
}


uint32_t 
pet_socket_send_capacity(struct socket * sock)
{
    size_t capacity = 0;
    
    pthread_mutex_lock(&(sock->lock));
    {
        capacity = pet_ringbuf_used_space(sock->send_buf);
    }
    pthread_mutex_unlock(&(sock->lock));

    return capacity;

}


/************************/
/* Global API functions */
/************************/

int
socket_init(struct petnet * petnet_state)
{
    struct socket_state * sock_state = NULL;
    
    
    sock_state = pet_malloc(sizeof(struct socket_state));

    memset(sock_state->fd_table, 0, sizeof(sock_state->fd_table));

    pthread_mutex_init(&(sock_state->lock), NULL);

    sock_state->tcp_port_map = port_map_create();
    sock_state->udp_port_map = port_map_create();
    

    petnet_state->socket_state = sock_state;


    return 0;
}