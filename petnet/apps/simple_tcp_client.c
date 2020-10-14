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
	pet_printf("Simple TCP Client:\n");
	pet_printf("Usage: simple_tcp_client <host> <port>\n");
}

int main(int argc, char ** argv)
{	
	struct sockaddr_in saddr;
	char * host_str = NULL;
	char * port_str = NULL;

	int sock_fd = 0;
	int ret     = 0;

	ret = __init_petnet();

	if (ret != 0) {
		log_error("Petnet failed to initialize\n");
		return -1;
	}

	if (argc != 3) {
		__usage();
		exit(-1);
	}

	host_str = argv[1];
	port_str = argv[2];



	sock_fd = petnet_socket(AF_INET, SOCK_STREAM, 0);

	if (sock_fd == -1) {
		log_error("Failed to create petnet socket (errno=%d)\n", petnet_errno);
		return -1;
	}

	memset(&saddr, 0, sizeof(struct sockaddr_in));

	saddr.sin_family = AF_INET;
	if (inet_aton(host_str, &(saddr.sin_addr)) == 0) {
		__usage();
		return -1;
	}
	saddr.sin_port = htons(atoi(port_str));


	ret = petnet_connect(sock_fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

	if (ret == -1) {
		log_error("Failed to connect petnet socket (errno=%d)\n", petnet_errno);
        return -1;
	}
	
	pet_printf("Connected\n");
	{
		uint8_t tmp[101];
		memset(tmp, 0, 101);

		while (1) {
			char * resp_str = NULL;
			int read = petnet_recv(sock_fd, tmp, 100);

			if (read == 0) {
				break;
			}

			pet_asprintf(&resp_str, "App received %d bytes: %s\n", read, tmp);
			printf("%s\n", resp_str);

			petnet_send(sock_fd, resp_str, strlen(resp_str) + 1);
			pet_free(resp_str);
			memset(tmp, 0, 101);
		}

		petnet_close(sock_fd);
	}


	return 0;
}