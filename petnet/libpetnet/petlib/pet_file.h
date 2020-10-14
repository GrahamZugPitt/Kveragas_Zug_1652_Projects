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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>



#include <limits.h>
#define PET_MAX_PATH_LEN PATH_MAX


typedef int pet_mode_t;


int
pet_read_file(const char  * path,
              uint8_t    ** buf,
              size_t      * size);


int
pet_write_file(const char * path,
               uint8_t    * buf,
               size_t       len);


/**
 * Creates an empty file
 * return 0 on success
 */
int
snk_touch_file(const char * path);

/**
 * This will delete a single file
 *  path must point to a file (not a directory)
 */
int
pet_delete_file(const char * path);



int
pet_mkdir(const char * path,
          pet_mode_t   mode);



bool
pet_dir_exists(const char * path);


bool
pet_file_exists(const char * path);

/**
 * This will recursively delete anything at or below the path location
 */
int
pet_delete_path(const char * path);



typedef void * pet_tmpfile_t;

#define pet_INVALID_TMPFILE NULL


pet_tmpfile_t
pet_write_tmpfile(uint8_t * buf,
                  size_t	len);


void 
pet_close_tmpfile(pet_tmpfile_t tmp_file);


#ifdef __cplusplus
}
#endif
