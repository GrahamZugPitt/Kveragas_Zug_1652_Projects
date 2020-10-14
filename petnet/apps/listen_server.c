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
	pet_printf("Simple TCP Server:\n");
	pet_printf("Usage: simple_tcp_server <port>\n");
}



int main(int argc, char ** argv)
{
	struct sockaddr_in saddr;

	char * port_str = NULL;;

	int sock_fd      = 0;


	int ret     = 0;

	ret = __init_petnet();

	if (ret != 0) {
		log_error("Petnet failed to initialize\n");
		return -1;
	}

	if (argc != 2) {
		__usage();
		exit(-1);
	}

	port_str = argv[1];

	sock_fd = petnet_socket(AF_INET, SOCK_STREAM, 0);

	if (sock_fd == -1) {
		log_error("Failed to create petnet socket (errno=%d)\n", petnet_errno);
		return -1;
	}

	memset(&saddr, 0, sizeof(struct sockaddr_in));

	saddr.sin_family      = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port        = htons(atoi(port_str));

	ret = petnet_bind(sock_fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

	if (ret == -1) {
		log_error("Failed to bind to socket (errno=%d)\n", petnet_errno);
		return -1;
	}

	ret = petnet_listen(sock_fd, 10);

	if (ret == -1) {
		log_error("Failed to listen on TCP socket (errno=%d)\n", petnet_errno);
		return -1;
	}

	while (1) {
		int client_sock  = 0;
		struct sockaddr_in daddr;
		socklen_t daddr_len = 0;
		
		char data_buf[1025];
		memset(data_buf, 0, 1025);

		client_sock = petnet_accept(sock_fd, (struct sockaddr *)&daddr, &daddr_len);

		if (client_sock == -1) {
			log_error("Failed to accept TCP connection (errno=%d)\n", petnet_errno);
			return -1;
		}

		pet_printf("Accepted Connnection (%d) from %s:%d\n", client_sock, inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));

		
		ret = petnet_recv(client_sock, data_buf, 1024);

		if (ret == -1) {
			log_error("Error receiving data from TCP connection (errno=%d)\n", petnet_errno);
			return -1;
		}

		pet_printf("Received %d bytes: %s\n", ret, data_buf);

		ret = petnet_send(client_sock, "Received Data\n", strlen("Received Data\n") + 1);

		if (ret == -1) {
			log_error("Error sending data to TCP connection (errno=%d)\n", petnet_errno);
			return -1;
		}

		pet_printf("Send %d bytes\n", strlen("Received Data\n") + 1);

		while (petnet_recv(client_sock, data_buf, 1024) != 0);

		petnet_close(client_sock);

	}

	return 0;
}