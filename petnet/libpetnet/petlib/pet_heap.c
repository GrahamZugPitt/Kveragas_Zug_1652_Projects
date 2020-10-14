/* 
Copyright (c) 2012, Armon Dadgar
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ARMON DADGAR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


/* This implementation was totally amateur hour, 
 * but it was quicker to clean it up than roll out a new one 
 * 
 * Modifications: 2020, Jack Lange
 * */

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#include "pet_util.h"
#include "pet_log.h"
#include "pet_heap.h"



#define LEFT_CHILD(i)   ((i << 1) + 1)
#define RIGHT_CHILD(i)  ((i << 1) + 2)
#define PARENT_INDEX(i) ((i - 1) >> 1)

/**
 * Stores the number of heap_entry structures
 * we can fit into a single page of memory.
 *
 * This is determined by the page size, so we
 * need to determine this at run time.
 */
static int __entries_per_page = 0;
static int __page_size        = 0;



static inline void
__swap_entries(struct pet_heap_entry * parent, 
               struct pet_heap_entry * child)
{
    void * tmp = NULL;
    
    tmp           = parent->key;
    parent->key   = child->key;
    child->key    = tmp;

    tmp           = parent->value;
    parent->value = child->value;
    child->value  = tmp;

    return;
}


// This is a comparison function that treats keys as signed ints
static int 
__compare_int_keys(register void * key1, 
                   register void * key2) 
{
    register int key1_v = *((int *)key1);
    register int key2_v = *((int *)key2);

    if (key1_v < key2_v) {
        return -1;
    } else if (key1_v == key2_v) {
        return 0;
    } else {
        return 1;
    }
}


static void *
__simple_mmap(uint32_t page_count)
{
    void * addr = mmap(NULL, 
                       page_count * __page_size, 
                       PROT_READ | PROT_WRITE, 
                       MAP_ANON  | MAP_PRIVATE, 
                       -1, 
                       0);

    if (addr == MAP_FAILED) {
        return NULL;
    }

    return addr;
}

// Creates a new heap
struct pet_heap *
pet_heap_create(int initial_size, 
                int (*comp_func)(void *, void *)) 
{
    struct pet_heap * heap  = NULL;

    uint32_t initial_page_count = 0;

    if (__page_size == 0) {
        __page_size        = getpagesize();
        __entries_per_page = __page_size / sizeof(struct pet_heap_entry);
    }

    if (initial_size <= 0) {
        initial_size = __entries_per_page;
    }

    
    if (comp_func == NULL) {
        comp_func = __compare_int_keys;
    }

    initial_page_count = (initial_size / __entries_per_page) + (initial_size % __entries_per_page > 0);


    heap = pet_malloc(sizeof(struct pet_heap));

    heap->cmp_fn          = comp_func;
    heap->active_entries  = 0;
    heap->allocated_pages = initial_page_count;
    heap->minimum_pages   = initial_page_count;
    heap->table           = __simple_mmap(initial_page_count);

    if (heap->table == NULL) {
        log_error("Could not mmap in heap table\n");
        goto err;
    }

    return heap;

err:
    if (heap)  pet_free_heap(heap);

    return NULL;
}



void 
pet_free_heap(struct pet_heap * heap)
{

    if (heap->table) {
        munmap(heap->table, heap->allocated_pages * __page_size);
    } 

    pet_free(heap);
}


size_t 
pet_heap_size(struct pet_heap * heap) 
{
    return (size_t)(heap->active_entries);
}


int 
pet_heap_peek(struct pet_heap *  heap, 
              void            ** key,
              void            ** value) 
{
    if (heap->active_entries == 0) {
        return -1;
    }

    /* Return values from Root entry */
    *key   = heap->table[0].key;
    *value = heap->table[0].value;

    return 0;
}



int 
pet_heap_insert(struct pet_heap * heap, 
                void            * key, 
                void            * value) 
{
    struct pet_heap_entry * parent  = NULL;
    struct pet_heap_entry * current = NULL;

    uint32_t current_idx = 0;
    uint32_t total_slots = heap->allocated_pages * __entries_per_page;


    /* We need to expand the heap */
    if ((heap->active_entries + 1) > total_slots) {
   
        int    new_pg_cnt = heap->allocated_pages * 2;
        void * new_table  = NULL;
        
        new_table = __simple_mmap(new_pg_cnt);

        if (new_table == NULL) {
            log_error("Could not allocate new heap table\n");
            return -1;
        }

        memcpy(new_table, heap->table, heap->allocated_pages * __page_size);
        munmap(heap->table, heap->allocated_pages * __page_size);

        heap->table           = new_table;
        heap->allocated_pages = new_pg_cnt;
    }
    
    current_idx = heap->active_entries;
    current     = &(heap->table[current_idx]);

    // While we can, keep swapping with our parent
    while (current_idx > 0) {
        parent = &(heap->table[PARENT_INDEX(current_idx)]);
    
        if (heap->cmp_fn(key, parent->key) >= 0) {
            break;
        }

        // Move the parent down
        current->key   = parent->key;
        current->value = parent->value;

        // Move our reference
        current_idx = PARENT_INDEX(current_idx);
        current     = parent;
}

    // Insert at the current idx
    current->key   = key;
    current->value = value; 

    heap->active_entries++;

    return 0;

}

int 
pet_heap_pop(struct pet_heap *  heap, 
             void            ** key, 
             void            ** value) 
{
    struct pet_heap_entry * current = NULL;

    uint32_t current_idx = 0;

    if (heap->active_entries == 0) {        
        return -1;
    }

    current = &(heap->table[0]);
    *key    = current->key;
    *value  = current->value;

    heap->active_entries--;
   
    // If there are any other nodes, we may need to move them up
    if (heap->active_entries > 0) {
        struct pet_heap_entry * last_entry  = &(heap->table[heap->active_entries]);
        struct pet_heap_entry * left_child  = NULL;
        struct pet_heap_entry * right_child = NULL;

        uint32_t left_child_idx = 0;

        // Move the last element to the root
        current->key   = last_entry->key;
        current->value = last_entry->value;

 
 
        while (LEFT_CHILD(current_idx) < heap->active_entries) {
            left_child_idx = LEFT_CHILD(current_idx);
            left_child     = &(heap->table[left_child_idx]);

            // We have a left + right child
            if ((left_child_idx + 1) < heap->active_entries) {
                right_child =  &(heap->table[left_child_idx + 1]);

                // Find the smaller child
                if (heap->cmp_fn(left_child->key, right_child->key) <= 0) {
                    // Left Child is smaller

                    // Only swap with the left if it is smaller
                    if (heap->cmp_fn(current->key, left_child->key) < 1) {
                        break;
                    }

                    __swap_entries(current, left_child);
                    current_idx = left_child_idx;
                    current     = left_child;

                } else {
                    // Right child is smaller

                    // Only swap with the right if it is smaller
                    if (heap->cmp_fn(current->key, right_child->key) < 1) {
                        break;
                    }
                    
                    __swap_entries(current, right_child);
                    current_idx = left_child_idx + 1;
                    current     = right_child;
                }


          
            } else if (heap->cmp_fn(current->key, left_child->key) == 1) {
                // We only have a left child, only do something if the left is smaller

                __swap_entries(current, left_child);
                current_idx = left_child_idx;
                current     = left_child;

            }  else {
                break;
            }
        }
    } 

    
    uint32_t used_pages =  (heap->active_entries / __entries_per_page) + 
                          ((heap->active_entries % __entries_per_page) > 0);


    if ((heap->allocated_pages / 2 >  used_pages + 1) &&
        (heap->allocated_pages / 2 >= heap->minimum_pages)) {
        int    new_pg_cnt = heap->allocated_pages / 2;
        void * new_table  = NULL;

        new_table = __simple_mmap(new_pg_cnt);

        if (new_table == NULL) {
            log_error("Could not allocate smaller heap table\n");
            return 0;
        }

        memcpy(new_table,   heap->table, used_pages * __page_size);
        munmap(heap->table, heap->allocated_pages * __page_size);

        heap->table           = new_table;
        heap->allocated_pages = new_pg_cnt;
    }

    return 0;
}


void 
pet_heap_foreach(struct pet_heap * heap, 
                 void (*map_fn)(void *, void *))
{
    struct pet_heap_entry * iter = NULL;

    uint32_t i = 0;

    for (i = 0; i < heap->active_entries; i++) {
        iter = &(heap->table[i]);

        map_fn(iter->key, iter->value);
    }
}


