/*
 * CS 1652 Project 1 
 * (c) Jack Lange, 2020
 * (c) <Taylor Kvergas, Graham Zug>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFSIZE 1024

int main(int argc, char ** argv) 
{

    char * server_name = NULL;
    int    server_port = -1;
    char * server_path = NULL;
    char * req_str     = NULL;

    int ret = 0;

    /*parse args */
    if (argc != 4) {
        fprintf(stderr, "usage: http_client <hostname> <port> <path>\n");
        exit(-1);
    }
	int s;
	char buf[BUFSIZE];
	struct hostent *hp;
	struct sockaddr_in server_address;
 	server_name = argv[1];
	server_port = atoi(argv[2]);
	server_path = argv[3];
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(server_port);
    

    ret = asprintf(&req_str, "GET  /%s HTTP/1.0\r\n\r\n", server_path);

    if (ret == -1) {
        fprintf(stderr, "Failed to allocate request string.\n");
        exit(-1);
    }

    /* make socket */
	s = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
    	if(s < 0){
        	fprintf(stderr, "Failed to make socket.\n");
		return -1; //Error Processing 
	}

    /* get host IP address  */
	if((hp = gethostbyname(server_name)) == NULL){
        	fprintf(stderr, "Failed to get host IP address.\n");
		close(s);
		return -1; //Error Processing 
	}
    /*set address */
	memcpy(&server_address.sin_addr.s_addr, hp->h_addr, hp->h_length);
    /* connect to the server socket */
	if(connect(s, (struct sockaddr *) &server_address, sizeof(server_address)) < 0){
        	fprintf(stderr, "Failed to connect to host.\n");
		close(s);	
		return -1; //Error Processing 
	}
    /* send request message */	
	int res = 0;
	if((res = write(s,req_str,strlen(req_str))) <= 0){
        	fprintf(stderr, "Failed to send request to server.\n");
		close(s);	
		return -1; //Error Processing 
	}
	//printf("%s", req_str); DELETE ME
    /* wait till socket can be read. */
    /* Hint: use select(), and ignore timeout for now. */
    /* first read loop -- read headers */

	if((res = read(s,buf,sizeof(buf) - 1)) <= 0){
        	fprintf(stderr, "Failed to read message from server.\n");
		close(s);	
		return -1; //Error Processing 
	}
	
    /* Check for 200 OK */ 	
	if(strstr(buf, "200 OK") == NULL){	
		for(int i = 0; i < res; i++)
			fprintf(stderr, "%c", buf[i]);
		while((res = read(s,buf,strlen(buf) - 1)) > 0){
			for(int i = 0; i < res; i++)
				fprintf(stderr, "%c", buf[i]);
		}
		close(s);
		shutdown(s, 2);
		return -1;
	}

    /* print first part of response: header, error code, etc. */
	for(int i = 0; i < res; i++)
		fprintf(stderr, "%c", buf[i]);
	
    /* second read loop -- print out the rest of the response: real web content */
	while((res = read(s,buf,strlen(buf) - 1)) > 0){	
		for(int i = 0; i < res; i++)
			fprintf(stderr, "%c", buf[i]);
		if(buf[res-1] == '\n' && buf[res-2] == '\r'){
			break;
			}
	}
	if(res < 0){
		fprintf(stderr, "Error occured while reading packets sent from server \n");
	}

    /*close socket and deinitialize */
	close(s);	
	shutdown(s, 2);
	return 0;


}
