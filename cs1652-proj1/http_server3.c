
/*
 * CS 1652 Project 1 
 * (c) Jack Lange, 2020
 * (c) <Student names here>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/socket.h>


#include "pet_list.h"
#include "pet_hashtable.h"


#define FILENAMESIZE 100
#define BUFSIZE      1024


/* Global connection tracking structure */
/* Either: 
    struct list_head connection_list = LIST_HEAD_INIT(connection_list);
    struct pet_hashtable * connection_table = NULL;
 */



struct connection {
    int       sock;
    int       fd;

    /* Fill this in */

};


/*
 * You are not required to use this function, but can use it or modify it as you see fit 
 */
static void 
send_response(struct connection * con) 
{
    char * ok_response_f  = "HTTP/1.0 200 OK\r\n"     					\
       					    "Content-type: text/plain\r\n"              \
        				    "Content-length: %d \r\n\r\n";
    
    char * notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"  			\
        					"Content-type: text/html\r\n\r\n"           \
        					"<html><body bgColor=black text=white>\n"   \
        					"<h2>404 FILE NOT FOUND</h2>\n"             \
        					"</body></html>\n";
    
	(void)notok_response; // DELETE ME
	(void)ok_response_f;  // DELETE ME

    /* send headers */

    /* send response */
  

}

/*
 * You are not required to use this function, but can use it or modify it as you see fit 
 */
static void 
handle_file_data(struct connection * con) 
{
	/* Read available file data */

	/* Check if we have read entire file */

	/* If we have read the entire file, send response to client */

}


/*
 * You are not required to use this function, but can use it or modify it as you see fit 
 */
static void 
handle_request(struct connection * con)
{
    /* parse request to get file name */

    /* Assumption: For this project you only need to handle GET requests and filenames that contain no spaces */

    /* get file  size */

    /* try opening the file */
    
    /* set to non-blocking */

	/* Initiate non-blocking file read operations */
}

/*
 * You are not required to use this function, but can use it or modify it as you see fit 
 */
static void 
handle_network_data(struct connection * con) 
{

	/* Read all available request data */

	/* Check if we have received all the headers */

	/* If we have all the headers check if we have the entire request */

	/* If we have the entire request, then handle the request */
}






int
main(int argc, char ** argv) 
{
    int server_port = -1;

    /* parse command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: http_server3 port\n");
        exit(-1);
    }

    server_port = atoi(argv[1]);

    if (server_port < 1500) {
        fprintf(stderr, "INVALID PORT NUMBER: %d; can't be < 1500\n", server_port);
        exit(-1);
    }
    
    /* Initialize connection tracking data structure */

    /* initialize and make server socket */

    /* set server address */

    /* bind listening socket */

    /* start listening */

    /* set up for connection handling loop */

    while (1) {

        /* create read and write lists */

        /* do a select */

        /* process socket descriptors that are ready */

        /* process file descriptors that are ready */

    }
}

