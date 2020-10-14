/* 
 * Copyright (c) 2017, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <ftw.h>

#include "pet_util.h"
#include "pet_log.h"
#include "pet_file.h"



int
pet_read_file(const char     * path,
              uint8_t       ** buf,
              size_t         * size)
{
	FILE        * file_ptr = NULL;
	struct stat   file_stats;
    
	size_t        file_size  = 0;
	uint8_t     * file_data = NULL;
    
	int ret = 0;
    
	ret = stat(path, &file_stats);

	if (ret == -1) {
		log_error("Could not stat file (%s)\n", path);
		return -1;
	}

	file_size = file_stats.st_size;

	if (file_size <= 0) {
		*size = 0;
		*buf = (uint8_t *)pet_malloc(1);

		return 0;
	}


	// We add an extra byte here to make sure strings are NULL terminated
	file_data = (uint8_t *)pet_malloc(file_size + 1); 

	file_ptr  = fopen(path, "rb");

	if (file_ptr == NULL) {
		log_error("Could not open file (%s)\n", path);
		goto out;
	}

	ret = fread(file_data, file_size, 1, file_ptr);

	ret--; /* This is a funky op to make the ret value be correct 
	        * fread will return 1 on success, and 0 on error (see fread man page)
	        */

	if (ret == -1) {
		pet_free(file_data);
		goto out;
	}

	*buf  = file_data;
	*size = file_size;
    
 out:
	fclose(file_ptr);
    
	return ret;
}



int
pet_write_file(const char   * path,
               uint8_t      * buf,
               size_t         size)
{
	FILE * file_ptr = NULL;

	int ret = 0;

	file_ptr = fopen(path, "wb");

	if (file_ptr == NULL) {
		log_error("Failed top open file (%s)\n", path);
		return -1;
	}

	ret = fwrite(buf, size, 1, file_ptr);

	ret--; /* This is a funky op to make the ret value be correct 
	        * fread will return 1 on success, and 0 on error (see fwrite man page)
	        */

	if (ret == -1) {
		log_error("Failed to write file (%s) (size=%zu)", path, size);
	}

	fclose(file_ptr);

	return ret;
}

bool
pet_dir_exists(const char * path)
{
	DIR * dir = NULL;

	dir = opendir(path);

	if (dir) {
		closedir(dir);
		return true;
	}

	return false;
}

bool
pet_file_exists(const char * path)
{
	FILE * file = NULL;

	file = fopen(path, "r");

	if (file) {
		fclose(file);
		return true;
	}

	return false;
}



int
pet_mkdir(const char * path,
          pet_mode_t   mode)
{
	return mkdir(path, mode);

}

int
pet_touch_file(const char * filepath)
{
	FILE * fd = NULL;

	fd = fopen(filepath, "wb");

	if (fd == NULL) {
		log_error("could not create file (%s)\n", filepath);
		return -1;
	}

	fclose(fd);

	return 0;
}

int
pet_delete_file(const char * path)
{
	int ret = 0;

	ret = remove(path);

	if (ret == -1) {
		log_error("Could not delete file (%s)\n", path);
	}
    
	return ret;
}


static int
delete_fn(const char        * fpath,
          const struct stat * sb,
          int                 typeflag,
          struct FTW        * ftwbuf)
{
	log_debug("Deleting: %s\n", fpath);

	return remove(fpath);
}




int
pet_delete_path(const char * path)
{
	int ret = 0;

	log_debug("Deleting Path: %s\n", path);
    
	ret = nftw(path, delete_fn, 20, FTW_DEPTH);

	return ret;
}


struct pet_tmpfile {
	FILE * file_ptr;
};


pet_tmpfile_t
pet_write_tmpfile(uint8_t * buf,
                  size_t	len)
{
	struct pet_tmpfile * tmp_file = NULL;
	FILE               * file_ptr = NULL;

	int ret = 0;

	file_ptr = tmpfile();

	if (file_ptr == NULL) {
		goto err;
	}

	ret = fwrite(buf, len, 1, file_ptr);

	if (ret == 0) {
		log_error("Failed to write tmpfile (size=%zu)", len);
		goto err;
	}


	tmp_file = pet_malloc(sizeof(struct pet_tmpfile));

	tmp_file->file_ptr = file_ptr;

	return tmp_file;
 err:

	if (tmp_file)  pet_free(tmp_file);
	if (file_ptr) fclose(file_ptr);

	return pet_INVALID_TMPFILE;
}


void
pet_close_tmpfile(pet_tmpfile_t arg)
{
	struct pet_tmpfile * tmp_file = (struct pet_tmpfile *)arg;

	fclose(tmp_file->file_ptr);
	pet_free(tmp_file);
}
