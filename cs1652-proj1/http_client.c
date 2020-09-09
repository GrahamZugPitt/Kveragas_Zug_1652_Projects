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

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFSIZE 1024

int 
main(int argc, char ** argv) 
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

    server_name = argv[1];
    server_port = atoi(argv[2]);
    server_path = argv[3];
    


    ret = asprintf(&req_str, "GET %s HTTP/1.0\r\n\r\n", server_path);

    if (ret == -1) {
        fprintf(stderr, "Failed to allocate request string\n");
        exit(-1);
    }

    /*
     * NULL accesses to quiesce compiler errors
     * Delete the following lines 
     */
    (void)server_name;
    (void)server_port;

    /* make socket */

    /* get host IP address  */
    /* Hint: use gethostbyname() */

    /* set address */

    /* connect to the server socket */

    /* send request message */

    /* wait till socket can be read. */
    /* Hint: use select(), and ignore timeout for now. */

    /* first read loop -- read headers */

    /* examine return code */   

    //Skip "HTTP/1.0"
    //remove the '\0'

    // Normal reply has return code 200

    /* print first part of response: header, error code, etc. */

    /* second read loop -- print out the rest of the response: real web content */

    /*close socket and deinitialize */


}