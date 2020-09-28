/*
 * CS 1652 Project 1 
 * (c) Jack Lange, 2020
 * (c) <Graham Zug, Taylor Kveragas>
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
#define SERVER_BACKLOG 10


static int 
handle_connection(int sock) 
{
 
    char * ok_response_f  = "HTTP/1.0 200 OK\r\n"						\
                            "Content-type: text/plain\r\n"				\
                            "Content-length: %d \r\n\r\n";
    
    char * notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"			\
                            "Content-type: text/html\r\n\r\n"			\
                            "<html><body bgColor=black text=white>\n"	\
                            "<h2>404 FILE NOT FOUND</h2>\n"				\
                            "</body></html>\n";
    
 //(void)notok_response;  // DELETE ME
 //(void)ok_response_f;   // DELETE ME

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
    //Stores file name in buffer
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
    /* Assumption: For this project you only need to handle GET requests and filenames that contain no spaces */
  
    /* open and read the file */
  int file = open(filename, 0);
    if(file == -1){ //Checks to see that file was opened correctly
        write(sock, notok_response, strlen(notok_response));
        close(sock);
        return -1;
        }
    int theEndOfTheFile = lseek(file, 0, SEEK_END); //sets pointer to end of file to get size of file in bytes
    sprintf(buf2, ok_response_f, theEndOfTheFile); //writes ok response to buffer to we can specify file size
    lseek(file, 0, SEEK_SET); //resets pointer
    
    write(sock, buf2, strlen(buf2));

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
    /* close socket and free space */
    close(sock);
    return 0;
}



int
main(int argc, char ** argv)
{
    int server_port = -1;
    //int ret         =  0;
    //int sock        = -1;

    /* parse command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: http_server1 port\n");
        exit(-1);
    }

    server_port = atoi(argv[1]);

    if (server_port < 1500) {
        fprintf(stderr, "Requested port(%d) must be above 1500\n", server_port);
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
        if(listen(server_socket, SERVER_BACKLOG) < 0){ //This means 10 people are allowed to connect (I think?)
            fprintf(stderr, "Failed to bind port.\n");
            close(server_socket);
            return -1; //Error Processing 
    }

    /* connection handling loop: wait to accept connection */

    /* create read list */
    fd_set curr_socket, temp_socket;
    FD_ZERO(&curr_socket);
    FD_ZERO(&temp_socket);
    FD_SET(server_socket, &curr_socket);

    int max = server_socket;
    while (1) {
        temp_socket = curr_socket; //select changes fd_set we pass in
    
    /* do a select */
        if(select(max+1, &temp_socket, NULL, NULL, NULL) < 0){
            fprintf(stderr, "Select returned an error.\n");
            close(server_socket);
            return -1; //Error Processing
        }

    /* process sockets that are ready */
        for(int i = 0; i < max+1; i++){
            if(FD_ISSET(i, &temp_socket)){
    /* for the accept socket, add accepted connection to connections */
                if(i == server_socket){
                    int client_socket = accept(server_socket, NULL, NULL);
                    if(client_socket < 0){
                        fprintf(stderr, "Error accepting connection.\n");
                        close(server_socket);
                        return -1;
                    }
                    if(client_socket > max){
                        max = client_socket;
                    }
                    FD_SET(client_socket, &curr_socket);
                
    /* for a connection socket, handle the connection */              
                }else{
                    if(handle_connection(i)< 0){
                        fprintf(stderr, "Error handling connection.\n");
                        close(server_socket);
                        return -1; //Error Processing 
                    }
                    FD_CLR(i,&curr_socket);
                }
            }
          
        }
    }
    return 0;
}
