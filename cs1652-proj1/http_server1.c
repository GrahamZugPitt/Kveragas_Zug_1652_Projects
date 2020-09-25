/*
 * CS 1652 Project 1 
 * (c) Jack Lange, 2020
 * (c) <Student names here>
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
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>


#define BUFSIZE 1024
#define FILENAMESIZE 100


static int 
handle_connection(int sock) 
{

    char * ok_response_f  = "HTTP/1.0 200 OK\r\n"        \
        					"Content-type: text/plain\r\n"                  \
        					"Content-length: %d \r\n\r\n";
 
    char * notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"   \
        					"Content-type: text/html\r\n\r\n"                       \
        					"<html><body bgColor=black text=white>\n"               \
        					"<h2>404 FILE NOT FOUND</h2>\n"
        					"</body></html>\n";

    /* first read loop -- get request and headers*/
	char buf[BUFSIZE];
	char buf2[sizeof(notok_response)]; //Initialize buffers	
	if(read(sock, buf, sizeof(buf) - 1) < 0){
        	fprintf(stderr, "Failed to read message from client.\n");
		close(sock);			
	}
    /* parse request to get file name */
	int pointer = 0;
	for(int i = 0; i < BUFSIZE; i++){
		if(buf[i] == '/'){
			pointer = i+1;
			for(int j = i; j < BUFSIZE; j++){
				if(isspace(buf[j]))
					pointer++;
				else{
					break;
				}
			}
		i = BUFSIZE + 1;
		}
	}
	char filename[FILENAMESIZE];
	
	for(int i = 0; i < FILENAMESIZE + pointer + 1; i++){
		if(i == (FILENAMESIZE + pointer)){
			write(sock, notok_response, strlen(notok_response));
			close(sock);
			return 0;			
		}
		if(!isspace(buf[pointer])){
			filename[i] = buf[pointer++];

		}
		else{
			filename[i] = '\0';
			break;
		}
	
	}
    /* open and read the file */
	int file = open(filename, 0);
	int theEndOfTheFile = lseek(file, 0, SEEK_END);
	sprintf(buf2, ok_response_f, theEndOfTheFile);
	lseek(file, 0, SEEK_SET);
	if(file == -1){
		write(sock, notok_response, strlen(notok_response));
		close(sock);
		return -1;
		}
	
	write(sock, buf2, strlen(buf2)); //The reason I use this buffer is because I need to change the %d to the actual size
	/* send response */
		int track = 0;
		while((track = read(file, buf, strlen(buf))) > 0){
			if(track < 0){
				printf("Error reading file. \n");	
				close(sock);
				return -1;
			}
			write(sock, buf, track);
			}
    /* close socket and free pointers */
	close(sock);
	return 0;
}


int 
main(int argc, char ** argv)
{
    int server_port = -1;

    /* parse command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: http_server1 port\n");
        exit(-1);
    }

    server_port = atoi(argv[1]);

    if (server_port < 1500) {
        fprintf(stderr, "INVALID PORT NUMBER: %d; can't be < 1500\n", server_port);
        exit(-1);
    }

    /* initialize and make socket */

	int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    	if(server_socket < 0){
        	fprintf(stderr, "Failed to make socket.\n");
		return -1; //Error Processing 
	}
    /* set server address*/
	struct sockaddr_in server_address;
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(server_port);
		server_address.sin_addr.s_addr = INADDR_ANY;

    /* bind listening socket */
	if(bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address)) < 0){
        	fprintf(stderr, "Failed to bind port.\n");
		close(server_socket);	
		return -1; //Error Processing 
	}
	
    /* start listening */
	if(listen(server_socket, 10) < 0){
        	fprintf(stderr, "Failed to bind port.\n");
		close(server_socket);
		return -1; //Error Processing 
	} 
    /* connection handling loop: wait to accept connection */
    while (1) {
        int client_socket = accept(server_socket, NULL, NULL);
        handle_connection(client_socket);
    }
}
