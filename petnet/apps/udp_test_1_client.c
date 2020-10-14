/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	


#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>


#include <petnet.h>
#include <petnet_socket_api.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>





struct petnet * petnet = NULL;

static int 
__init_petnet()
{
	petnet = petnet_init_from_config("./config.json");

	if (petnet == NULL) {
		printf("Error initializing Petnet\n");
		return -1;
	}

    log_error("Huh??\n");
	petnet_run(petnet);

	return 0;
}


static void 
__usage()
{
	pet_printf("UDP Test 1 client:\n");
	pet_printf("Usage: udp_test_1_client <ip address> <port> <msg>\n");
}




int main(int argc, char ** argv)
{
	struct sockaddr_in remote_addr;
	socklen_t          remote_addr_len = sizeof(struct sockaddr_in);


	char * msg_data = NULL;

    char * host_str = NULL;
	char * port_str = NULL;
	int    sock_fd  = 0;

	int ret = 0;


	ret = __init_petnet();

	if (ret != 0) {
		goto err;
	}

	if (argc != 4) {
		__usage();
		return -1;
	}

    host_str = argv[1];
	port_str = argv[2];
	msg_data = argv[3];

    log_error("Creating socket...\n");
	sock_fd = petnet_socket(AF_INET, SOCK_DGRAM, 0);

	if (sock_fd == -1) {
		log_error("Failed to create petnet socket (errno=%d)\n", petnet_errno);
		goto err;
	}

	memset(&remote_addr, 0, sizeof(struct sockaddr_in));

	remote_addr.sin_family      = AF_INET;
	remote_addr.sin_addr.s_addr = inet_addr(host_str);
	remote_addr.sin_port        = htons(atoi(port_str));


    log_error("Sending datagram\n");
	ret = petnet_sendto(sock_fd, msg_data, strlen(msg_data), 0, (struct sockaddr *)&remote_addr, remote_addr_len);

	if (ret == -1) {
		log_error("Could not receive datagram (errno=%d)\n", petnet_errno);
		goto err;
	}

    sleep(5);

	petnet_close(sock_fd);


	pet_printf("TEST PASSED\n");
	return 0;

err:
	pet_printf("TEST FAILED\n");
	return -1;
}