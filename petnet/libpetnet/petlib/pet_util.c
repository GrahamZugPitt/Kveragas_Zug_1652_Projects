/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>


#include <unistd.h>
#include <sys/syscall.h>
#include <linux/random.h>


#include <string.h>

#include "pet_util.h"
#include "pet_log.h"






#ifdef USE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>

void
pet_print_backtrace()
{
	unw_cursor_t cursor; 
	unw_context_t uc;


	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	
	pet_printf("Backtrace:\n");

	while (unw_step(&cursor) > 0) {
		unw_word_t offset;
		char  buf[1025];

		memset(buf, 0, 1025);

		unw_get_proc_name(&cursor, buf, 1024, &offset);

		pet_printf ("\t%s:%d\n", buf, offset);
	}
}

#else

#include <execinfo.h>

/* Not thread safe... */
#define BACKTRACE_SIZE 128
static void * backtrace_buffer[BACKTRACE_SIZE];


void
pet_print_backtrace()
{
	int     sym_cnt  = 0;
	char ** sym_strs = NULL;

	int i = 0;
    
	sym_cnt  = backtrace(backtrace_buffer, BACKTRACE_SIZE);

	log_error("Backtrace: (sym_cnt = %d)\n", sym_cnt);

	sym_strs = backtrace_symbols(backtrace_buffer, sym_cnt);
    
	if (sym_strs == NULL) {
		/* Failed to translate symbols, print out the raw addresses */

		log_error("Error: Could not translate symbols\n");
	
		for (i = 0; i < sym_cnt; i++) {
			log_error("\t(%p)\n", backtrace_buffer[i]); 
		}

	} else {

		for (i = 0; i < sym_cnt; i++) {
			log_error("\t%s\n", sym_strs[i]); 
		}

		pet_free(sym_strs);
	}
    
	return;
}
#endif


void
pet_free_internal(void * ptr)
{
	free(ptr);
	return;
}

void *
pet_calloc(size_t cnt, size_t size)
{ 
	return pet_malloc(cnt * size);
}

void *
pet_malloc(size_t size)
{
	void * ptr = NULL;


	ptr = calloc(size, 1);

	if (ptr == NULL) {
		/* This should never happen, but if it does 
		 * it means we are almost certainly going down hard. 
		 * Try to print out what we can, but note that the 
		 * failures are most likely cascading here. There 
		 * is a good chance nothing will show up, and we 
		 * might still crash on a segfault.
		 */
		log_error("Malloc Failure for size %lu\n", size);
		pet_exit();
	}


	return ptr;
}

void *
pet_realloc(void   * ptr,
            size_t   size)
{
	void * new_ptr = NULL;

	new_ptr = realloc(ptr, size);

	return new_ptr;

}


int
pet_get_rand_bytes(uint8_t * buf,
                   size_t    bytes)
{

	unsigned int flags = 0;
	int ret = 0;

	/* For small (most) cases use true random bytes */
	if (bytes <= 128) {
		flags = GRND_RANDOM;
	}

	/*       
	 * getrandom is somewhat new, and unsupported by glibc versions before 2.25
	 *   There is some macro magic that could do the right thing here, but this should work 
	 * ret = getrandom(buf, bytes, flags);
	 */
	ret = syscall(SYS_getrandom, buf, bytes, flags);

	if (ret != (int)bytes) {
		log_error("Getrandom failed: ret=%d\n", ret);
		return -1;
	}

	return 0;


}

int
pet_atomic_inc(int * val)
{
	int ret = 1;

	asm volatile ("lock xaddl %1, %0"
				  : "+m" (*val), "+r" (ret)
				  : 
				  : "memory");

	return ret + 1;
}

int 
pet_atomic_dec(int * val)
{
	int ret = -1;

	asm volatile ("lock xaddl %1, %0"
				  : "+m" (*val), "+r" (ret)
				  : 
				  : "memory");

	return ret - 1;
}



void
pet_exit()
{

	pet_print_backtrace();
	exit(-1);
}


char *
pet_strndup(const char * src,
            size_t       max_size)
{

	char * new_str = strndup(src, max_size);
	return new_str;
}


int
pet_vasprintf(char       ** strp,
              const char *  fmt,
              va_list       args)
{
	char * tmp_str = NULL;
	int    size    = 0;
	int    ret     = 0;
	va_list tmp_args;

	va_copy(tmp_args, args);

	*strp = NULL;
	size  = vsnprintf(NULL, 0, fmt, tmp_args) + 1;
    
	if (size < 0) {
		return -1;
	}

	tmp_str = (char *)pet_malloc(size);

	ret = vsnprintf(tmp_str, size, fmt, args);

	if (ret == -1) {
		pet_free(tmp_str);
		return -1;
	}

	*strp = tmp_str;
	return ret;
}


int
pet_asprintf(char       ** strp,
             const char *  fmt,
             ...)
{
    
	va_list args;
	int ret = 0;

	va_start(args, fmt);
	ret = pet_vasprintf(strp, fmt, args);
	va_end(args);

	return ret;
}

char *
pet_str_append(char * dst,
               char * str)
{
	char * new_str = NULL;
	int    str_len = 0;
    
	log_debug("appending (%s) to (%s)\n", str, dst);

	if (dst) {
		str_len = strlen(dst);
	}


	new_str = pet_malloc(str_len + strlen(str) + 1);

	if (dst) {
		memcpy(new_str, dst, str_len);
		pet_free(dst);
	}
    
	strncat(new_str, str, strlen(str));

	return new_str;
}


char *
pet_str_join(char  * joint,
             int     cnt,
             char ** str_array)
{
	char * str = NULL;
	int i = 0;

	if (cnt == 0) {
		/* Return an empty string (only contains '\0') */
		return (char *)pet_malloc(1);
	}
    
	str = pet_str_append(str, str_array[0]);
    
	for (i = 1; i < cnt; i++) {
		str = pet_str_append(str, joint);
		str = pet_str_append(str, str_array[i]);
	}

	return str;
}


// https://gist.github.com/ccbrown/9722406
void
pet_hexdump(void   * ptr,
            size_t   size)
{
	uint8_t * data = (uint8_t *)ptr;
	char      ascii[17];
	char      hex[50];
    
	size_t    i    = 0;
	size_t    j    = 0;
    
	for (i = 0; i < size; i += 16) {
		char * tmp_str = hex;
	
		memset(ascii, 0, sizeof(ascii));
		memset(hex,   0, sizeof(hex));

		for (j = 0; j < 16; j++) {
			char ascii_char = '.';

			if ((i + j) >= size) {
				snprintf(tmp_str, 4, "   ");
			} else {
				snprintf(tmp_str, 4, "%.2x ", data[i + j]);

				if ((data[i + j] >= ' ') &&
				    (data[i + j] <= '~') ) {
					ascii_char = data[i + j];
				}
			}

			ascii[j] = ascii_char;
	    
			tmp_str += 3;	    	    
		}

		pet_printf("%.8x  %s |%s|\n", i, hex, ascii);

	}

}

int
pet_strtou8(char    * str,
            uint8_t * value)
{
	unsigned long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtoul(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if (tmp > UCHAR_MAX) {
		/* value exceeded requested size */
		return -1;
	}
	   
	*value = (uint8_t)tmp;    
	return 0;
}

int
pet_strtoi8(char    * str,
            int8_t * value)
{
	long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtol(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if ((tmp > SCHAR_MAX) ||
	    (tmp < SCHAR_MIN)) {
		/* value exceeded requested size */
		return -1;
	}
	   	
	*value = (int8_t)tmp;    
	return 0;
}



int
pet_strtou16(char     * str,
             uint16_t * value)
{
	unsigned long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtoul(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if (tmp > USHRT_MAX) {
		/* value exceeded requested size */
		return -1;
	}
	   
	*value = (uint16_t)tmp;    
	return 0;
}

int
pet_strtoi16(char     * str,
             int16_t * value)
{
	long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtol(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if ((tmp > SHRT_MAX) ||
	    (tmp < SHRT_MIN)) {
		/* value exceeded requested size */
		return -1;
	}
	   	
	*value = (int16_t)tmp;    
	return 0;
}

int
pet_strtou32(char     * str,
             uint32_t * value)
{
	unsigned long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtoul(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   
	*value = (uint32_t)tmp;    
	return 0;
}

int
pet_strtoi32(char     * str,
             int32_t * value)
{
	long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtol(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   	
	*value = (int32_t)tmp;    
	return 0;
}


int
pet_strtou64(char     * str,
             uint64_t * value)
{
	unsigned long long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtoull(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   
	*value = (uint64_t)tmp;    
	return 0;
}
int
pet_strtoi64(char    * str,
             int64_t * value)
{
	long long tmp = 0;

	char * end  = NULL;
	int    base = 0;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	if (strlen(str) > 2) {
		if ((*(str + 1) == 'x') ||
		    (*(str + 1) == 'X')) {
			base = 16;
		}
	}

	tmp = strtoll(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   	
	*value = (int64_t)tmp;    
	return 0;
}


int
pet_strtou8_hex(char    * str,
            	uint8_t * value)
{
	unsigned long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	tmp = strtoul(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if (tmp > UCHAR_MAX) {
		/* value exceeded requested size */
		return -1;
	}
	   
	*value = (uint8_t)tmp;    
	return 0;
}

int
pet_strtoi8_hex(char   * str,
          		int8_t * value)
{
	long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	tmp = strtol(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if ((tmp > SCHAR_MAX) ||
	    (tmp < SCHAR_MIN)) {
		/* value exceeded requested size */
		return -1;
	}
	   	
	*value = (int8_t)tmp;    
	return 0;
}



int
pet_strtou16_hex(char     * str,
             	 uint16_t * value)
{
	unsigned long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}

	tmp = strtoul(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if (tmp > USHRT_MAX) {
		/* value exceeded requested size */
		return -1;
	}
	   
	*value = (uint16_t)tmp;    
	return 0;
}

int
pet_strtoi16_hex(char    * str,
             	 int16_t * value)
{
	long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}

	tmp = strtol(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}

	if ((tmp > SHRT_MAX) ||
	    (tmp < SHRT_MIN)) {
		/* value exceeded requested size */
		return -1;
	}
	   	
	*value = (int16_t)tmp;    
	return 0;
}

int
pet_strtou32_hex(char     * str,
             	 uint32_t * value)
{
	unsigned long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}

	tmp = strtoul(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   
	*value = (uint32_t)tmp;    
	return 0;
}

int
pet_strtoi32_hex(char     * str,
            	 int32_t * value)
{
	long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}

	tmp = strtol(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   	
	*value = (int32_t)tmp;    
	return 0;
}


int
pet_strtou64_hex(char     * str,
           		 uint64_t * value)
{
	unsigned long long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}
    
	tmp = strtoull(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   
	*value = (uint64_t)tmp;    
	return 0;
}
int
pet_strtoi64_hex(char    * str,
            	 int64_t * value)
{
	long long tmp = 0;

	char * end  = NULL;
	int    base = 16;
    
    
	if ((str == NULL) || (*str == '\0')) {
		/*  String was either NULL or empty */
		log_error("Invalid string\n");
		return -1;
	}

	tmp = strtoll(str, &end, base);

	if (end == str) {
		/* String contained non-numerics */
		return -1;
	}
	   	
	*value = (int64_t)tmp;    
	return 0;
}



