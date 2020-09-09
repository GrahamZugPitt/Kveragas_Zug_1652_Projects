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

#include "pet_hashtable.h"

/* 
 * This is an example of how to use hashtables in the pet_hashtable.[ch] 
 * Fair warning: There are a number of unsafe C idioms here that you should ignore. 
 *               They are only used so as to avoid distracting from the hashtable API itself. 
 * 
 * To compile in Ubuntu make sure the libreadline-dev package is installed
 */

struct pet_hashtable * test_table = NULL;


struct str_buffer {
    char * str;
    int    key;
};

static int 
__u32_eq_fn(uintptr_t val1, 
            uintptr_t val2)
{
    return ((uint32_t)val1 == (uint32_t)val2);
}

static void
__free_buffer_fn(uintptr_t val)
{
    struct str_buffer * buf = (struct str_buffer *)val;

    free(buf->str);
    free(buf);
}


int 
main(int argc, char ** argv)
{
    int i = 0;

    printf("Hashtable API example\n");

    /* 
     * Create a hashtable 
     * pet_hash_u32() is provided via pet_hashtable.h, the other functions we provide ourselves
     */
    test_table = pet_create_htable(0, pet_hash_u32, __u32_eq_fn, __free_buffer_fn, NULL);


    /* 
     * Add all command line arguments to the hash table, keyed to their index within the argument list
     */
    for (i = 1; i < argc; i++) {
        struct str_buffer * new_buf = calloc(sizeof(struct str_buffer), 1);

        new_buf->str = strdup(argv[i]);
        new_buf->key = i;

        pet_htable_insert(test_table, (uintptr_t)(new_buf->key), (uintptr_t)new_buf);
    }


    {
        char * index_str = readline("Index to delete: ");
        int    index     = atoi(index_str);

        /* Search for string in hash table associated with key index */
        struct str_buffer * buf = pet_htable_search(test_table, (uintptr_t)index);

        if (buf == NULL) {
            /* Error: Could not locate index in the hash table. */
            printf("Error: Could not find string index (%d)\n", index);
            return -1;
        }

        printf("Found string at index (%d): %s\n", buf->key, buf->str);

        /* 
         * Remove string from table
         * This will automatically free the buffer because we specified a free function in pet_htable_create() 
         */
        pet_htable_remove(test_table, (uintptr_t)index);

    }


}
