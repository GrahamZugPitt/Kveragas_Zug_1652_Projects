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


#include "pet_json.h"

#include "pet_util.h"
#include "pet_log.h"



/* Internalize nxjson functions */
#include "nxjson.h"
#include "nxjson.c"


pet_json_obj_t
pet_json_new_obj(char * key)
{
	return create_json(NX_JSON_OBJECT, key, NULL);
}


pet_json_obj_t
pet_json_new_arr(char * key)
{
	return create_json(NX_JSON_ARRAY, key, NULL);
}

pet_json_obj_t
pet_json_parse_str(char * str)
{
	pet_json_obj_t new_obj = PET_JSON_INVALID_OBJ;

	new_obj = nx_json_parse(str);

	if (new_obj == NULL) {
		log_error("Could not parse JSON string (%s)\n", str);
		return PET_JSON_INVALID_OBJ;
	}

	return new_obj;
}

char *
pet_json_serialize(pet_json_obj_t obj)
{
	return nx_json_serialize(obj);
}

			     
void
pet_json_free(pet_json_obj_t object)
{
	assert(object != NULL);

	assert(((struct nx_json *)object)->root == 1);

	nx_json_free(object);

	return;
}


pet_json_obj_t
pet_json_get_object(pet_json_obj_t   obj,
                    char             * key)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return PET_JSON_INVALID_OBJ;
	}

	if (tgt_obj->type != NX_JSON_OBJECT) {
		return PET_JSON_INVALID_OBJ;
	}
    
    
	return tgt_obj;
}

int
pet_json_add_object(pet_json_obj_t   root_obj,
                    pet_json_obj_t   new_obj)
{
    
	return nx_json_splice(root_obj, new_obj);
}

int
pet_json_splice(pet_json_obj_t   obj,
                pet_json_obj_t   new_obj)
{
	return nx_json_splice(obj, new_obj);
}


int
pet_json_split(pet_json_obj_t obj)
{
	return nx_json_split(obj);
}


int
pet_json_del_object(pet_json_obj_t obj)
{
	nx_json_free(obj);
	return 0;
}


int
pet_json_del_by_key(pet_json_obj_t   obj,
                    char             * key)
{
	nx_json_del(obj, key);
	return 0;
}








int
pet_json_get_string(pet_json_obj_t   obj,
                    char             * key,
                    char            ** val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_STRING) {
		return -1;
	}

	*val = tgt_obj->text_value;
    
	return 0;
}


int
pet_json_get_bool(pet_json_obj_t   obj,
                  char             * key,
                  int              * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_BOOL) {
		return -1;
	}

	if ((tgt_obj->int_value != 0) &&
	    (tgt_obj->int_value != 1)) {
		return -1;
	}
    
	*val = tgt_obj->int_value;
    
	return 0;
}


int
pet_json_get_int(pet_json_obj_t   obj,
                 char             * key,
                 int              * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if ((tgt_obj->int_value > INT_MAX) ||
	    (tgt_obj->int_value < INT_MIN)) {
		log_error("PET_JSON_INT: Bounds Error\n");
		return -1;
	}
    
	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_get_double(pet_json_obj_t   obj,
                    char             * key,
                    double           * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_DOUBLE) {
		return -1;
	}

	*val = tgt_obj->dbl_value;
    
	return 0;
}


int
pet_json_get_s8(pet_json_obj_t   obj,
                char             * key,
                int8_t           * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}


	if ((tgt_obj->int_value > SCHAR_MAX) ||
	    (tgt_obj->int_value < SCHAR_MIN)) {
		log_error("PET_JSON_S8: Bounds Error\n");
		return -1;
	}

	*val = tgt_obj->int_value;
    
	return 0;
}

int
pet_json_get_s16(pet_json_obj_t   obj,
                 char             * key,
                 int16_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if ((tgt_obj->int_value > SHRT_MAX) ||
	    (tgt_obj->int_value < SHRT_MIN)) {
		log_error("PET_JSON_S16: Bounds Error\n");
		return -1;
	}
    
	*val = tgt_obj->int_value;
    
	return 0;
}

int
pet_json_get_s32(pet_json_obj_t   obj,
                 char             * key,
                 int32_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if ((tgt_obj->int_value > INT_MAX) ||
	    (tgt_obj->int_value < INT_MIN)) {
		log_error("PET_JSON_S32: Bounds Error\n");
		return -1;
	}
    
	*val = tgt_obj->int_value;
    
	return 0;
}


int
pet_json_get_s64(pet_json_obj_t   obj,
                 char             * key,
                 int64_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}
    
	*val = tgt_obj->int_value;
    
	return 0;
}


int
pet_json_get_u8(pet_json_obj_t   obj,
                char             * key,
                uint8_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if (tgt_obj->int_value > UCHAR_MAX) {
		log_error("PET_JSON_U8: Bounds Error\n");
		return -1;
	}
	
	*val = tgt_obj->int_value;
    
	return 0;
}

int
pet_json_get_u16(pet_json_obj_t   obj,
                 char             * key,
                 uint16_t         * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if (tgt_obj->int_value > USHRT_MAX) {
		log_error("PET_JSON_U16: Bounds Error\n");
		return -1;
	}

	*val = tgt_obj->int_value;
    
	return 0;
}

int
pet_json_get_u32(pet_json_obj_t   obj,
                 char             * key,
                 uint32_t         * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if (tgt_obj->int_value > UINT_MAX) {
		log_error("PET_JSON_U32: Bounds Error\n");
		return -1;
	}
    
	*val = tgt_obj->int_value;
    
	return 0;
}

int
pet_json_get_u64(pet_json_obj_t   obj,
                 char             * key,
                 uint64_t         * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get(obj, key);

	if (tgt_obj == NULL) {
		return -1;
	}

	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	*val = tgt_obj->int_value;
    
	return 0;
}



int
pet_json_add_string(pet_json_obj_t   obj,
                    char           * key,
                    char           * str)
{
	struct nx_json new_json;

	new_json.type       = NX_JSON_STRING;
	new_json.text_value = str; // pet_strndup(str, MAX_JSON_LEN);

	return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);
}


int
pet_json_add_bool(pet_json_obj_t   obj,
                  char             * key,
                  int                val)
{
	struct nx_json new_json;

	new_json.type      = NX_JSON_BOOL;
	new_json.int_value = val;

	return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
}

int
pet_json_add_int(pet_json_obj_t   obj,
                 char             * key,
                 int                val)
{
	struct nx_json new_json;

	new_json.type      = NX_JSON_INTEGER;
	new_json.int_value = val;

	return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
}

int
pet_json_add_double(pet_json_obj_t   obj,
                    char             * key,
                    double             val)
{
	struct nx_json new_json;

	new_json.type      = NX_JSON_DOUBLE;
	new_json.dbl_value = val;

	return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
}

int
pet_json_add_s64(pet_json_obj_t   obj,
                 char             * key,
                 int64_t            val)
{
	struct nx_json new_json;

	new_json.type      = NX_JSON_INTEGER;
	new_json.int_value = val;

	return ((nx_json_add(obj, key, &new_json) == NULL) ? -1 : 0);    
}

int
pet_json_add_u64(pet_json_obj_t   obj,
                 char             * key,
                 uint64_t           val)
{
	return pet_json_add_s64(obj, key, val);
}

int
pet_json_add_s8(pet_json_obj_t   obj,
                char             * key,
                int8_t             val)
{
	return pet_json_add_s64(obj, key, val);
}

int
pet_json_add_s16(pet_json_obj_t   obj,
                 char             * key,
                 int16_t            val)
{
	return pet_json_add_s64(obj, key, val);
}

int
pet_json_add_s32(pet_json_obj_t   obj,
                 char             * key,
                 int32_t            val)
{
	return pet_json_add_s64(obj, key, val);
}

							                  
int
pet_json_add_u8(pet_json_obj_t   obj,
                char             * key,
                uint8_t            val)
{
	return pet_json_add_s64(obj, key, val);
}

int
pet_json_add_u16(pet_json_obj_t   obj,
                 char             * key,
                 uint16_t           val)
{
	return pet_json_add_s64(obj, key, val);
}

int
pet_json_add_u32(pet_json_obj_t   obj,
                 char             * key,
                 uint32_t           val)
{
	return pet_json_add_s64(obj, key, val);
}








int
pet_json_set_string(pet_json_obj_t   obj,
                    char           * key,
                    char           * str)
{
	struct nx_json new_val;

	new_val.type       = NX_JSON_STRING;
	new_val.text_value = str; // pet_strndup(str, MAX_JSON_LEN);

	return nx_json_set(obj, key, &new_val);
}


int
pet_json_set_bool(pet_json_obj_t   obj,
                  char             * key,
                  int                val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_BOOL;
	new_val.int_value = val;

	return nx_json_set(obj, key, &new_val);    
}

int
pet_json_set_int(pet_json_obj_t   obj,
                 char             * key,
                 int                val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_INTEGER;
	new_val.int_value = val;

	return nx_json_set(obj, key, &new_val);    
}

int
pet_json_set_double(pet_json_obj_t   obj,
                    char             * key,
                    double             val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_DOUBLE;
	new_val.dbl_value = val;

	return nx_json_set(obj, key, &new_val);    
}

int
pet_json_set_s64(pet_json_obj_t   obj,
                 char             * key,
                 int64_t            val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_INTEGER;
	new_val.int_value = val;

	return nx_json_set(obj, key, &new_val);    
}

int
pet_json_set_u64(pet_json_obj_t   obj,
                 char             * key,
                 uint64_t           val)
{
	return pet_json_set_s64(obj, key, val);
}

int
pet_json_set_s8(pet_json_obj_t   obj,
                char             * key,
                int8_t             val)
{
	return pet_json_set_s64(obj, key, val);
}

int
pet_json_set_s16(pet_json_obj_t   obj,
                 char             * key,
                 int16_t            val)
{
	return pet_json_set_s64(obj, key, val);
}

int
pet_json_set_s32(pet_json_obj_t   obj,
                 char             * key,
                 int32_t            val)
{
	return pet_json_set_s64(obj, key, val);
}

							                  
int
pet_json_set_u8(pet_json_obj_t   obj,
                char             * key,
                uint8_t            val)
{
	return pet_json_set_s64(obj, key, val);
}

int
pet_json_set_u16(pet_json_obj_t   obj,
                 char             * key,
                 uint16_t           val)
{
	return pet_json_set_s64(obj, key, val);
}

int
pet_json_set_u32(pet_json_obj_t   obj,
                 char             * key,
                 uint32_t           val)
{
	return pet_json_set_s64(obj, key, val);
}






pet_json_obj_t
pet_json_get_array(pet_json_obj_t   obj,
                   char             * key)
{
	struct nx_json * tgt_obj = NULL;
    
	tgt_obj = nx_json_get(obj, key);
    
	if (tgt_obj == NULL) {
		return PET_JSON_INVALID_OBJ;
	}

	if (tgt_obj->type != NX_JSON_ARRAY) {
		return PET_JSON_INVALID_OBJ;
	}    
    
	return tgt_obj;
}

int
pet_json_get_array_len(pet_json_obj_t arr)
{
	return ((struct nx_json *)arr)->length;
}


pet_json_obj_t
pet_json_add_array(pet_json_obj_t   obj,
                   char             * key)
{
	struct nx_json new_json;
    
	new_json.type = NX_JSON_ARRAY;
    
	return nx_json_add(obj, key, &new_json);
}


int
pet_json_del_array(pet_json_obj_t obj)
{
	nx_json_free(obj);
	return 0;
}


pet_json_obj_t
pet_json_array_get_object(pet_json_obj_t   arr,
                          int                idx)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return PET_JSON_INVALID_OBJ;
	}
	
	if (tgt_obj->type != NX_JSON_OBJECT) {
		return PET_JSON_INVALID_OBJ;
	}

	return tgt_obj;
}



int
pet_json_array_get_string(pet_json_obj_t    arr,
                          int               idx,
                          char           ** val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_STRING) {
		return -1;
	}

	*val = tgt_obj->text_value;

	return 0;
}

int
pet_json_array_get_bool(pet_json_obj_t   arr,
                        int              idx,
                        int            * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_BOOL) {
		return -1;
	}

	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_int(pet_json_obj_t   arr,
                       int                idx,
                       int              * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if ((tgt_obj->int_value > INT_MAX) ||
	    (tgt_obj->int_value < INT_MIN)) {
		log_error("PET_JSON_INT: Bounds Error\n");
		return -1;
	}
    
	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_double(pet_json_obj_t   arr,
                          int                idx,
                          double           * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_DOUBLE) {
		return -1;
	}

	*val = tgt_obj->dbl_value;

	return 0;
}

int
pet_json_array_get_s8(pet_json_obj_t   arr,
                      int                idx,
                      int8_t           * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}


	if ((tgt_obj->int_value > SCHAR_MAX) ||
	    (tgt_obj->int_value < SCHAR_MIN)) {
		log_error("PET_JSON_S8: Bounds Error\n");
		return -1;
	}

    
	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_s16(pet_json_obj_t   arr,
                       int                idx,
                       int16_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if ((tgt_obj->int_value > SHRT_MAX) ||
	    (tgt_obj->int_value < SHRT_MIN)) {
		log_error("PET_JSON_S16: Bounds Error\n");
		return -1;
	}

	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_s32(pet_json_obj_t   arr,
                       int                idx,
                       int32_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if ((tgt_obj->int_value > INT_MAX) ||
	    (tgt_obj->int_value < INT_MIN)) {
		log_error("PET_JSON_S32: Bounds Error\n");
		return -1;
	}

	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_s64(pet_json_obj_t   arr,
                       int                idx,
                       int64_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_u8(pet_json_obj_t   arr,
                      int                idx,
                      uint8_t          * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}
    
	if (tgt_obj->int_value > UCHAR_MAX) {
		log_error("PET_JSON_U8: Bounds Error\n");
		return -1;
	}


	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_u16(pet_json_obj_t   arr,
                       int                idx,
                       uint16_t         * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if (tgt_obj->int_value > USHRT_MAX) {
		log_error("PET_JSON_U16: Bounds Error\n");
		return -1;
	}

	*val = tgt_obj->int_value;

	return 0;
}


int
pet_json_array_get_u32(pet_json_obj_t   arr,
                       int                idx,
                       uint32_t         * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	if (tgt_obj->int_value > UINT_MAX) {
		log_error("PET_JSON_U32: Bounds Error\n");
		return -1;
	}

	*val = tgt_obj->int_value;

	return 0;
}

int
pet_json_array_get_u64(pet_json_obj_t   arr,
                       int                idx,
                       uint64_t         * val)
{
	struct nx_json * tgt_obj = NULL;

	tgt_obj = nx_json_get_item(arr, idx);

	if (tgt_obj == NULL) {
		return -1;
	}
	
	if (tgt_obj->type != NX_JSON_INTEGER) {
		return -1;
	}

	*val = tgt_obj->int_value;

	return 0;
}




/* 
 * Set the value of an existing array item 
 */




int
pet_json_array_set_string(pet_json_obj_t   arr,
                          int              idx,
                          char           * str)
{
	struct nx_json new_val;

	new_val.type       = NX_JSON_STRING;
	new_val.text_value = str;

	return nx_json_set_item(arr, idx, &new_val);
}


int
pet_json_array_set_bool(pet_json_obj_t arr,
                        int              idx,
                        int              val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_BOOL;
	new_val.int_value = val;

	return nx_json_set_item(arr, idx, &new_val);    
}

int
pet_json_array_set_int(pet_json_obj_t arr,
                       int              idx,
                       int              val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_INTEGER;
	new_val.int_value = val;

	return nx_json_set_item(arr, idx, &new_val);    
}

int
pet_json_array_set_double(pet_json_obj_t arr,
                          int              idx,
                          double           val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_DOUBLE;
	new_val.dbl_value = val;

	return nx_json_set_item(arr, idx, &new_val);    
}

int
pet_json_array_set_s64(pet_json_obj_t arr,
                       int              idx,
                       int64_t          val)
{
	struct nx_json new_val;

	new_val.type      = NX_JSON_INTEGER;
	new_val.int_value = val;

	return nx_json_set_item(arr, idx, &new_val);    
}

int
pet_json_array_set_u64(pet_json_obj_t arr,
                       int              idx,
                       uint64_t         val)
{
	return pet_json_array_set_s64(arr, idx, val);
}

int
pet_json_array_set_s8(pet_json_obj_t arr,
                      int              idx,
                      int8_t           val)
{
	return pet_json_array_set_s64(arr, idx, val);
}

int
pet_json_array_set_s16(pet_json_obj_t arr,
                       int              idx,
                       int16_t          val)
{
	return pet_json_array_set_s64(arr, idx, val);
}

int
pet_json_array_set_s32(pet_json_obj_t arr,
                       int              idx,
                       int32_t          val)
{
	return pet_json_array_set_s64(arr, idx, val);
}

							                  
int
pet_json_array_set_u8(pet_json_obj_t arr,
                      int              idx,
                      uint8_t          val)
{
	return pet_json_array_set_s64(arr, idx, val);
}

int
pet_json_array_set_u16(pet_json_obj_t arr,
                       int              idx,
                       uint16_t         val)
{
	return pet_json_array_set_s64(arr, idx, val);
}

int
pet_json_array_set_u32(pet_json_obj_t arr,
                       int              idx,
                       uint32_t         val)
{
	return pet_json_array_set_s64(arr, idx, val);
}


/* 
 * Add a new item to an existing array 
 */


int
pet_json_array_add_object(pet_json_obj_t   arr,
                          int            * idx,
                          pet_json_obj_t   obj)
{

	int tmp_idx = 0;

	tmp_idx = nx_json_array_splice(arr, obj);

	if (idx) *idx = tmp_idx;
    
	return 0;
}



int
pet_json_array_add_string(pet_json_obj_t   arr,
                          int            * idx,
                          char           * val)
{
	struct nx_json new_val;
	int tmp_idx = 0;
    
	new_val.type       = NX_JSON_STRING;
	new_val.text_value = val; //pet_strndup(val, MAX_JSON_LEN);
    
	tmp_idx = nx_json_add_item(arr, &new_val);

	if (idx) *idx = tmp_idx;

	return 0;
}



int
pet_json_array_add_bool(pet_json_obj_t   arr,
                        int            * idx,
                        int              val)
{
	struct nx_json new_val;
	int tmp_idx = 0;
    
	new_val.type      = NX_JSON_BOOL;
	new_val.int_value = val;

	tmp_idx = nx_json_add_item(arr, &new_val);

	if (idx) *idx = tmp_idx;
    
	return 0;
}

int
pet_json_array_add_int(pet_json_obj_t   arr,
                       int            * idx,
                       int              val)
{
	struct nx_json new_val;
	int tmp_idx = 0;
    
	new_val.type      = NX_JSON_INTEGER;
	new_val.int_value = val;
    
	tmp_idx = nx_json_add_item(arr, &new_val);

	if (idx) *idx = tmp_idx;
    
	return 0;
}

int
pet_json_array_add_double(pet_json_obj_t   arr,
                          int            * idx,
                          double           val)
{
	struct nx_json new_val;
	int tmp_idx = 0;

    
	new_val.type      = NX_JSON_DOUBLE;
	new_val.dbl_value = val;

	tmp_idx = nx_json_add_item(arr, &new_val);    

	if (idx) *idx = tmp_idx;
    
	return 0;
}

int
pet_json_array_add_s64(pet_json_obj_t   arr,
                       int            * idx,
                       int64_t          val)
{
	struct nx_json new_val;
	int tmp_idx = 0;

	new_val.type      = NX_JSON_INTEGER;
	new_val.int_value = val;

	tmp_idx = nx_json_add_item(arr, &new_val);    

	if (idx) *idx = tmp_idx;

	return 0;
}

int
pet_json_array_add_u64(pet_json_obj_t   arr,
                       int            * idx,
                       uint64_t         val)
{
	return pet_json_array_add_s64(arr, idx, val);
}

int
pet_json_array_add_s8(pet_json_obj_t   arr,
                      int            * idx,
                      int8_t           val)
{
	return pet_json_array_add_s64(arr, idx, val);
}

int
pet_json_array_add_s16(pet_json_obj_t   arr,
                       int            * idx,
                       int16_t          val)
{
	return pet_json_array_add_s64(arr, idx, val);
}

int
pet_json_array_add_s32(pet_json_obj_t   arr,
                       int            * idx,
                       int32_t          val)
{
	return pet_json_array_add_s64(arr, idx, val);
}

							                  
int
pet_json_array_add_u8(pet_json_obj_t   arr,
                      int            * idx,
                      uint8_t          val)
{
	return pet_json_array_add_s64(arr, idx, val);
}

int
pet_json_array_add_u16(pet_json_obj_t   arr,
                       int            * idx,
                       uint16_t         val)
{
	return pet_json_array_add_s64(arr, idx, val);
}

int
pet_json_array_add_u32(pet_json_obj_t   arr,
                       int            * idx,
                       uint32_t         val)
{
	return pet_json_array_add_s64(arr, idx, val);
}





/* Delete an array item at index idx */
int
pet_json_array_del_idx(pet_json_obj_t arr,
                       int            idx)
{
	nx_json_del_item(arr, idx);
	return 0;
}


int
pet_json_array_del_item(pet_json_obj_t arr,
                        pet_json_obj_t item)
{
	nx_json_free(item);
	return 0;
}






/* Fills in parameter structure with results from a parsed JSON string
 * Return Value:
 *  0 = Success
 *  1 = More tokens than params
 * -1 = Parse Error
 */

int
pet_json_get_params(pet_json_obj_t          obj,
                    struct pet_json_param * params,
                    uint32_t                  num_params)
{
	uint32_t i   = 0;
	int      ret = 0;
    
	/* Check Params and grab values */
	for (i = 0; i < num_params; i++) {

		switch (params[i].type) {
			case PET_JSON_U8:
				ret = pet_json_get_u8 (obj, params[i].name, (uint8_t  *)&params[i].val);
				break;
			case PET_JSON_S8:
				ret = pet_json_get_s8 (obj, params[i].name, (int8_t   *)&params[i].val);
				break;
			case PET_JSON_U16:
				ret = pet_json_get_u16(obj, params[i].name, (uint16_t *)&params[i].val);
				break;
			case PET_JSON_S16:
				ret = pet_json_get_s16(obj, params[i].name, (int16_t  *)&params[i].val);
				break;
			case PET_JSON_U32:
				ret = pet_json_get_u32(obj, params[i].name, (uint32_t *)&params[i].val);
				break;
			case PET_JSON_S32:
				ret = pet_json_get_s32(obj, params[i].name, (int32_t  *)&params[i].val);
				break;
			case PET_JSON_U64:
				ret = pet_json_get_u64(obj, params[i].name, (uint64_t *)&params[i].val);
				break;
			case PET_JSON_S64:
				ret = pet_json_get_s64(obj, params[i].name, (int64_t  *)&params[i].val);
				break;
			case PET_JSON_STRING: {	       
				ret = pet_json_get_string(obj, params[i].name, (char **)&params[i].ptr);
				break;
			}
			case PET_JSON_OBJECT:
				log_error("PET_JSON_OBJECT not currently supported\n");
				goto out;
			default:
				log_error("Error Invalid Parameter Type (%d)\n", params[i].type);
				goto out;
		}
	
	
	}


 out:   
	if (ret < 0) {
		log_error("Error Parsing JSON value\n");
	}
    
  
	return ret;
    
}

