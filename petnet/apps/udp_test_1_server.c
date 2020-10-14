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

	petnet_run(petnet);

	return 0;
}


static void 
__usage()
{
	pet_printf("UDP Test 1 server:\n");
	pet_printf("Usage: udp_test_1_server <port> <expected msg>\n");
}




int main(int argc, char ** argv)
{
	struct sockaddr_in local_addr;
	struct sockaddr_in remote_addr;
	socklen_t          remote_addr_len = sizeof(struct sockaddr_in);


	char * expected_data = NULL;
	char buf[2049];

	char * port_str = NULL;
	int    serv_fd  = 0;

	int ret = 0;


	ret = __init_petnet();

	if (ret != 0) {
		goto err;
	}

	if (argc != 3) {
		__usage();
		return -1;
	}

	port_str      = argv[1];
	expected_data = argv[2];

	serv_fd = petnet_socket(AF_INET, SOCK_DGRAM, 0);

	if (serv_fd == -1) {
		log_error("Failed to create petnet socket (errno=%d)\n", petnet_errno);
		goto err;
	}

	memset(&local_addr, 0, sizeof(struct sockaddr_in));

	local_addr.sin_family      = AF_INET;
	local_addr.sin_addr.s_addr = INADDR_ANY;
	local_addr.sin_port        = htons(atoi(port_str));

	ret = petnet_bind(serv_fd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr_in));

	if (ret == -1) {
		log_error("Failed to bind to socket (errno=%d)\n", petnet_errno);
		goto err;
	}

	ret = petnet_recvfrom(serv_fd, buf, 2048, 0, (struct sockaddr *)&remote_addr, &remote_addr_len);

	if (ret == -1) {
		log_error("Could not receive datagram (errno=%d)\n", petnet_errno);
		goto err;
	}

	petnet_close(serv_fd);


	if (ret != (int)strlen(expected_data)) {
		log_error("Message length mismatch\n");
		goto err;
	}

	if (strncmp(buf, expected_data, ret) != 0) {
		goto err;
	}

	pet_printf("TEST PASSED\n");
	return 0;

err:
	pet_printf("TEST FAILED\n");
	return -1;
}