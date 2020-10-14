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

/*
 * Author: Armon Dadgar
 *
 * Header for the Heap functions and data definitions
 */

#ifndef __PET_HEAP_H__
#define __PET_HEAP_H__

#include <stdint.h>
#include <stdlib.h>

// Structure for a single heap entry
struct pet_heap_entry {
    void * key;   // Key for this entry
    void * value; // Value for this entry
};


// Main struct for representing the heap
struct pet_heap {
    int (*cmp_fn)(void *, void *);  // The key comparison function to use
    uint32_t active_entries;                   // The number of entries in the heap
    uint32_t minimum_pages;                    // The minimum number of pages to maintain, based on the initial cap.
    uint32_t allocated_pages;             // The number of pages in memory that are allocated

    struct pet_heap_entry * table;        // Pointer to the table, which maps to the pages
};

// Functions

/**
 * Creates a new heap
 * @param h Pointer to a heap structure that is initialized
 * @param initial_size What should the initial size of the heap be. If <= 0, then it will be set to the minimum
 * permissable size, of 1 page (512 entries on 32bit system with 4K pages).
 * @param comp_func A pointer to a function that can be used to compare the keys. If NULL, it will be set
 * to a function which treats keys as signed ints. This function must take two keys, given as pointers and return an int.
 * It should return -1 if key 1 is smaller, 0 if they are equal, and 1 if key 2 is smaller.
 */
struct pet_heap * pet_heap_create(int initial_size, int (*cmp_fn)(void *, void *));

/**
 * Returns the size of the heap
 * @param h Pointer to a heap structure
 * @return The number of entries in the heap.
 */
size_t pet_heap_size(struct pet_heap * heap);

/**
 * Inserts a new element into a heap.
 * @param h The heap to insert into
 * @param key The key of the new entry
 * @param value The value of the new entry
 */
int pet_heap_insert(struct pet_heap * heap, void * key, void * value);

/**
 * Returns the element with the smallest key in the heap.
 * @param h Pointer to the heap structure
 * @param key A pointer to a pointer, to set to the minimum key
 * @param value Set to the value corresponding with the key
 * @return 1 if the minimum element exists and is set, 0 if there are no elements.
 */
int pet_heap_peek(struct pet_heap * heap, void ** key, void ** value);

/**
 * Pops the element with the smallest key off the heap.
 * @param h Pointer to the heap structure
 * @param key A pointer to a pointer, to set to the minimum key
 * @param valu Set to the value corresponding with the key
 * @return 1if the minimum element exists and is deleted, 0 if there are no elements.
 */
int pet_heap_pop(struct pet_heap * heap, void ** key, void ** value);

/**
 * Calls a function for each entry in the heap.
 * @param h The heap to iterate over
 * @param func The function to call on each entry. Should take a void* key and value.
 */
void pet_heap_foreach(struct pet_heap * heap, void (*func)(void *, void *));

/**
 * Destroys and cleans up a heap.
 * @param h The heap to destroy.
 */
void pet_free_heap(struct pet_heap * heap);

#endif

