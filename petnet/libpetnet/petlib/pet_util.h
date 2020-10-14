/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
    
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include "pet_log.h"

void pet_exit();


void pet_free_internal(void *);

#define pet_free(ptr)			\
	do {  	                    \
		pet_free_internal(ptr);	\
		ptr = NULL;				\
	} while (0)

#define pet_free2(ptr)			\
	do {		                \
		pet_free_internal(ptr);	\
	} while (0)	
    

/* 
 * Return a random value of size /bytes/ in /buf/
 */
int pet_get_rand_bytes(uint8_t * buf, size_t bytes);

int pet_atomic_inc(int * val);
int pet_atomic_dec(int * val);



void * pet_malloc(size_t size);
void * pet_calloc(size_t cnt, size_t size);
void * pet_realloc(void * ptr, size_t size);

int pet_vasprintf(char ** strp, const char * fmt, va_list args);
int pet_asprintf(char ** strp, const char * fmt, ...);

char * pet_str_append(char * dst, char * str);
char * pet_str_join(char * joint, int cnt, char ** str_array);

char * pet_strndup(const char * src, size_t max_size);


void pet_hexdump(void * ptr, size_t size);


int pet_strtoi8 (char * str, int8_t   * value);
int pet_strtou8 (char * str, uint8_t  * value);
int pet_strtoi16(char * str, int16_t  * value);
int pet_strtou16(char * str, uint16_t * value);
int pet_strtoi32(char * str, int32_t  * value);
int pet_strtou32(char * str, uint32_t * value);
int pet_strtoi64(char * str, int64_t  * value);
int pet_strtou64(char * str, uint64_t * value);

int pet_strtoi8_hex (char * str, int8_t   * value);
int pet_strtou8_hex (char * str, uint8_t  * value);
int pet_strtoi16_hex(char * str, int16_t  * value);
int pet_strtou16_hex(char * str, uint16_t * value);
int pet_strtoi32_hex(char * str, int32_t  * value);
int pet_strtou32_hex(char * str, uint32_t * value);
int pet_strtoi64_hex(char * str, int64_t  * value);
int pet_strtou64_hex(char * str, uint64_t * value);

void pet_print_backtrace();

#ifdef __cplusplus
}
#endif
