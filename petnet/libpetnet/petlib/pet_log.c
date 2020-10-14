/* 
 * Copyright (c) 2018, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <pthread.h>

#include "pet_log.h"

void
pet_print_str(const char * str)
{
	pet_printf("%s", str);
}

void
pet_log_str(const char * str)
{
	pet_logf("%s", str);
}



void
pet_logf(const char * fmt, ...)
{
	struct timeval tv;

	va_list args;

	gettimeofday(&tv, NULL);

	fprintf(stdout, "PETNET[%lu] %lu.%06lu> ", pthread_self(), tv.tv_sec, tv.tv_usec);
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	fflush(stdout);

	return;
}


void
pet_printf(const char * fmt, ...)
{
	struct timeval tv;

	va_list args;

	gettimeofday(&tv, NULL);

	printf("PETNET[%lu] %lu.%06lu> ", pthread_self(), tv.tv_sec, tv.tv_usec);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	fflush(stdout);
	return;
}
