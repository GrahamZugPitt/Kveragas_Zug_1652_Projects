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
	pet_printf("Select based TCP Server:\n");
	pet_printf("Usage: select_server <port>\n");
}



int main(int argc, char ** argv)
{
	struct sockaddr_in saddr;

	char * port_str = NULL;;
	int    serv_fd  = 0;

	fd_set rd_set;
	fd_set wr_set;
	fd_set er_set;
	int    max_fd = 0;

	int ret = 0;


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

	serv_fd = petnet_socket(AF_INET, SOCK_STREAM, 0);

	if (serv_fd == -1) {
		log_error("Failed to create petnet socket (errno=%d)\n", petnet_errno);
		return -1;
	}

	memset(&saddr, 0, sizeof(struct sockaddr_in));

	saddr.sin_family      = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port        = htons(atoi(port_str));

	ret = petnet_bind(serv_fd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

	if (ret == -1) {
		log_error("Failed to bind to socket (errno=%d)\n", petnet_errno);
		return -1;
	}

	ret = petnet_listen(serv_fd, 10);

	if (ret == -1) {
		log_error("Failed to listen on TCP socket (errno=%d)\n", petnet_errno);
		return -1;
	}


	FD_ZERO(&rd_set);
	FD_ZERO(&wr_set);
	FD_ZERO(&er_set);

	FD_SET(serv_fd, &rd_set);
	max_fd = serv_fd + 1;


	while (1) {
		fd_set tmp_rd_set = rd_set;
		fd_set tmp_wr_set = wr_set;
	//	fd_set tmp_er_set = er_set;

		struct timeval timeout = {10, 0};

		int i = 0;



		
		pet_printf("Selecting\n");

		ret = petnet_select(max_fd, &tmp_rd_set, &tmp_wr_set, NULL, &timeout);


		pet_printf("Select returned %d\n", ret);


		if (ret == 0) {		
			pet_printf("Select timed out\n");
			continue;
		}

		if (ret == -1) {
			log_error("Select returned error\n");
			continue;
		}



		if (FD_ISSET(serv_fd, &tmp_rd_set)) {
			struct sockaddr_in daddr;
			socklen_t          daddr_len = 0;

			int new_fd = 0;

			memset(&daddr, 0, sizeof(struct sockaddr_in));

			pet_printf("Accepting on %d\n", serv_fd);

			new_fd = petnet_accept(serv_fd, (struct sockaddr *)&daddr, &daddr_len);

			if (new_fd == -1) {
				log_error("Failed to accept TCP connection (errno=%d)\n", petnet_errno);
				return -1;
			}

			pet_printf("Accepted Connnection (%d) from %s:%d\n", new_fd, inet_ntoa(daddr.sin_addr), ntohs(daddr.sin_port));

			FD_SET(new_fd, &rd_set);
			max_fd = (new_fd >= max_fd) ? new_fd + 1 : max_fd;
		}

		FD_CLR(serv_fd, &tmp_rd_set);
	
		pet_printf("Looping over connections\n");
		for (i = 0; i < max_fd; i++) {	
			if (FD_ISSET(i, &tmp_rd_set)) {
				char data_buf[1025];
				memset(data_buf, 0, 1025);
				
				pet_printf("Found connection %d\n", i);


				ret = petnet_recv(i, data_buf, 1024);

				if (ret == -1) {
					log_error("Error receiving data from TCP connection (errno=%d)\n", petnet_errno);
					return -1;
				}

				if (ret == 0) {
					pet_printf("Closing Connection %d\n", i);
					petnet_close(i);					
					FD_CLR(i, &rd_set);
				} else {

					pet_printf("Received %d bytes: %s\n", ret, data_buf);

					ret = petnet_send(i, "Received Data\n", strlen("Received Data\n") + 1);

					if (ret == -1) {
						log_error("Error sending data to TCP connection (errno=%d)\n", petnet_errno);
						return -1;
					}

					pet_printf("Send %d bytes\n", strlen("Received Data\n") + 1);
				}


			}
		}
	}

	return 0;
}