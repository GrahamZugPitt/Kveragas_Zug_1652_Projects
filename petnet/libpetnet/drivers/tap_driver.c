/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <unistd.h>
#include <string.h>
#include <ulimit.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/uio.h>


#include <petlib/pet_util.h>
#include <petlib/pet_log.h>

#include <petnet.h>
#include "pet_driver.h"

#include <core/packet.h>
#include <core/packet_pool.h>
#include <core/ethernet.h>




struct tap_driver {
    struct petnet_driver driver;

    int  tap_fd; 
  	char tap_name[IFNAMSIZ];

    pthread_t      rx_thread;
    pthread_attr_t rx_thread_attr;

	pthread_mutex_t tx_lock;

};


static int
__tap_tx(struct packet * pkt)
{
	struct tap_driver * driver_state = (struct tap_driver *)(petnet_state->driver);

	struct iovec pkt_vecs[4];

	ssize_t bytes_written  = 0;
	ssize_t bytes_to_write = pkt->layer_2_hdr_len +
							 pkt->layer_3_hdr_len + 
							 pkt->layer_4_hdr_len +
							 pkt->payload_len;

	if (bytes_to_write > petnet_state->device_mtu) {
		log_error("Cannot send packets larger than device MTU (%d)\n", petnet_state->device_mtu);
		return -1;
	}

	pkt_vecs[0].iov_base = pkt->layer_2_hdr;
	pkt_vecs[0].iov_len  = pkt->layer_2_hdr_len;
	pkt_vecs[1].iov_base = pkt->layer_3_hdr;
	pkt_vecs[1].iov_len  = pkt->layer_3_hdr_len;
	pkt_vecs[2].iov_base = pkt->layer_4_hdr;
	pkt_vecs[2].iov_len  = pkt->layer_4_hdr_len;
	pkt_vecs[3].iov_base = pkt->payload;
	pkt_vecs[3].iov_len  = pkt->payload_len;


	//	log_debug("Driver Transmitting Packet\n");

	pthread_mutex_lock(&(driver_state->tx_lock));
	{
		bytes_written = writev(driver_state->tap_fd, pkt_vecs, 4);
	}
	pthread_mutex_unlock(&(driver_state->tx_lock));
	
	/* 
	 * My understanding is that tap devices do not exhibit partial writes.
	 * If that is incorrect we'll need to fix this
	 */
	if (bytes_written != bytes_to_write) {
		log_error("Error writing packet to tap interface (ret=%d)\n", bytes_written);
		return -1;
	}

    return 0;
}

static void *
__tap_listen_fn(void * thread_data)
{
    struct tap_driver * tap_state    = (struct tap_driver *)petnet_state->driver;

	int  nread = 0;


	while (1) {
        struct packet * pkt = create_packet(petnet_state->device_mtu);
    
		

    	/* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */
		nread = read(tap_state->tap_fd, pkt->buf, pkt->buf_size);

		if (nread < 0) {
            log_error("Error reading tap interface\n");
			close(tap_state->tap_fd);
			pthread_exit(NULL);
		}

        pkt->buf_len = nread;

        ethernet_pkt_rx(pkt);

		free_packet(pkt);

	}

    return NULL;
}


static int 
__tap_listen()
{
    struct tap_driver * tap_state = (struct tap_driver *)petnet_state->driver;

    int ret = 0;

    ret = pthread_create(&(tap_state->rx_thread), &(tap_state->rx_thread_attr), __tap_listen_fn, NULL);

    if (ret != 0) {
        log_error("Could not launch driver receiver thread\n");
        return -1;
    }


    return 0;
}

static int
__tap_connect(struct tap_driver * tap_state)
{
	struct   ifreq ifr;
	char   * clonedev = "/dev/net/tun";
	int      fd       = 0;
    int      err      = 0;


	/* open the clone device */
	if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("open error: ");
		return fd;
	}

	/* preparation of the struct ifr, of type "struct ifreq" */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tap_state->tap_name, IFNAMSIZ);

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI; /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

	/* try to create the device */
	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl error: ");
		close(fd);
		return -1;
	}

    tap_state->tap_fd = fd;

	return 0;
}




int
tap_driver_init(struct petnet * petnet_state)
{
    struct tap_driver * tap_state = NULL;

    int ret = 0;

    tap_state = pet_malloc(sizeof(struct tap_driver));

    if (tap_state == NULL) {
        log_error("Could not allocate driver state\n");
        return -1;
    }
	
    strncpy(tap_state->tap_name, petnet_state->net_dev, IFNAMSIZ);

    tap_state->driver.tx     = __tap_tx;
    tap_state->driver.listen = __tap_listen;

    if (petnet_state->debug_enable) {
	    pet_printf("Tap name %s\n", petnet_state->net_dev);
	}

	/* Connect to the device */
	ret = __tap_connect(tap_state); 

	if (ret < 0) {
        log_error("Could not connect to tap interface (%s)\n", tap_state->tap_name);
	}

	pthread_mutex_init(&tap_state->tx_lock, NULL);

    petnet_state->driver = (struct petnet_driver *)tap_state;


    return 0;
}



#if 0
	int  nread = 0;
	char buffer[8192];


	/* Now read data coming from the kernel */
	while (1) {
		/* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */
		nread = read(tun_fd, buffer, sizeof(buffer));
		if (nread < 0) {
			perror("Reading from interface");
			close(tun_fd);
			exit(1);
		}

		/* Do whatever with the data */
		printf("Read %d bytes from device %s\n", nread, tun_name);
	}


	return 0;
}

#endif