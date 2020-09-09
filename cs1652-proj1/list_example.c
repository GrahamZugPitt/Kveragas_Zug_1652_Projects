/*
 * CS 1652 Project 1 
 * (c) Jack Lange, 2020
 * 
 * Computer Science Department
 * University of Pittsburgh
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <readline/readline.h>

#include "pet_list.h"

/* 
 * This is an example of how to use linked lists in the pet_list.h 
 * Fair warning: There are a number of unsafe C idioms here that you should ignore. 
 *               They are only used so as to avoid distracting from the linked list API itself. 
 * 
 * To compile in Ubuntu make sure the libreadline-dev package is installed
 */

LIST_HEAD(test_list);


struct str_buffer {
    char * str;
    int    idx;

    struct list_head node;
};



static void
__free_buffer(struct str_buffer * buf)
{
    free(buf->str);
    free(buf);
}


int 
main(int argc, char ** argv)
{
    int i = 0;

    printf("Linked List API example\n");



    /* 
     * Add all command line arguments to the linked list, 
     */
    for (i = 1; i < argc; i++) {
        struct str_buffer * new_buf = calloc(sizeof(struct str_buffer), 1);

        new_buf->str = strdup(argv[i]);
        new_buf->idx = i;

        list_add_tail(&(new_buf->node), &test_list);
    }


    {
        char * index_str = readline("Index to delete: ");
        int    index     = atoi(index_str);

        struct str_buffer * buf = NULL;

        /* Search for string in hash table associated with key index */
        list_for_each_entry(buf, &(test_list), node) {
            if (buf->idx == index) {
                break;
            }
        }
        

        if (buf == NULL) {
            /* Error: Could not locate index in the hash table. */
            printf("Error: Could not find string index (%d)\n", index);
            return -1;
        }

        printf("Found string at index (%d): %s\n", buf->idx, buf->str);

        /* 
         * Remove string from table
         * This will automatically free the buffer because we specified a free function in pet_htable_create() 
         */
        list_del(&(buf->node));

        __free_buffer(buf);
    }


}
