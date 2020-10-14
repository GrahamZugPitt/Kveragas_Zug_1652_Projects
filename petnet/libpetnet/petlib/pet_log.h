/* 
 * Copyright (c) 2018, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif



void pet_print_str(const char * str);
void pet_log_str(const char * str);
void pet_printf(const char * fmt, ...);
void pet_logf(const char * fmt, ...);

#define log_error(fmt, ...) pet_logf("error> %s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#if PET_ENABLE_DEBUG
#define log_debug(fmt, ...) pet_logf("debug> %s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define log_debug(fmt, ...)
#endif




#ifdef __cplusplus
}
#endif
