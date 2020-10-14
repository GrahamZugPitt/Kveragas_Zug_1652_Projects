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

#include <stdint.h>
#include <stdlib.h>

#define PET_JSON_INVALID_OBJ (NULL)


typedef void * pet_json_obj_t;

typedef enum {
	PET_JSON_U8,
	PET_JSON_S8,
	PET_JSON_U16,
	PET_JSON_S16,
	PET_JSON_U32,
	PET_JSON_S32,
	PET_JSON_U64,
	PET_JSON_S64,
	PET_JSON_STRING,
	PET_JSON_OBJECT
} pet_json_type_t;


struct pet_json_param {
	char              * name;

	pet_json_type_t   type;
    
	union {
		uintptr_t           val;    
		void             *  ptr;
	};
};


/* Batch query for a set of parameters */
int
pet_json_get_params(pet_json_obj_t          obj,
                    struct pet_json_param * params,
                    uint32_t                num_params);



pet_json_obj_t pet_json_new_obj(char * key);
pet_json_obj_t pet_json_new_arr(char * key);

int pet_json_splice(pet_json_obj_t   parent,
                    pet_json_obj_t   obj);

int pet_json_split(pet_json_obj_t obj);

pet_json_obj_t pet_json_parse_str(char * str);


char * pet_json_serialize(pet_json_obj_t obj);


/* Free a parsed JSON structure */
void pet_json_free(pet_json_obj_t object);



/* 
 * Object Accessors 
 */

pet_json_obj_t pet_json_get_object(pet_json_obj_t obj, char * key);
int            pet_json_del_object(pet_json_obj_t obj);
int            pet_json_add_object(pet_json_obj_t root_obj, pet_json_obj_t new_obj);


/* 
 * Object Member Accessors 
 */


/* Return a parameter directly from JSON
 * NOTE: Caller should not free these 
 */
int pet_json_get_string(pet_json_obj_t obj, char * key, char    ** val);

int pet_json_get_bool  (pet_json_obj_t obj, char * key, int      * val);
int pet_json_get_int   (pet_json_obj_t obj, char * key, int      * val);
int pet_json_get_double(pet_json_obj_t obj, char * key, double   * val);

int pet_json_get_s8    (pet_json_obj_t obj, char * key, int8_t   * val);
int pet_json_get_s16   (pet_json_obj_t obj, char * key, int16_t  * val);
int pet_json_get_s32   (pet_json_obj_t obj, char * key, int32_t  * val);
int pet_json_get_s64   (pet_json_obj_t obj, char * key, int64_t  * val);

int pet_json_get_u8    (pet_json_obj_t obj, char * key, uint8_t  * val);
int pet_json_get_u16   (pet_json_obj_t obj, char * key, uint16_t * val);
int pet_json_get_u32   (pet_json_obj_t obj, char * key, uint32_t * val);
int pet_json_get_u64   (pet_json_obj_t obj, char * key, uint64_t * val);

/* Set the values of currently existing parameters */

int pet_json_set_string(pet_json_obj_t obj, char * key, char * str);  
							                  
int pet_json_set_bool  (pet_json_obj_t obj, char * key, int      val);
int pet_json_set_int   (pet_json_obj_t obj, char * key, int      val);
int pet_json_set_double(pet_json_obj_t obj, char * key, double   val);
							                  
int pet_json_set_s8    (pet_json_obj_t obj, char * key, int8_t   val);
int pet_json_set_s16   (pet_json_obj_t obj, char * key, int16_t  val);
int pet_json_set_s32   (pet_json_obj_t obj, char * key, int32_t  val);
int pet_json_set_s64   (pet_json_obj_t obj, char * key, int64_t  val);
							                  
int pet_json_set_u8    (pet_json_obj_t obj, char * key, uint8_t  val);
int pet_json_set_u16   (pet_json_obj_t obj, char * key, uint16_t val);
int pet_json_set_u32   (pet_json_obj_t obj, char * key, uint32_t val);
int pet_json_set_u64   (pet_json_obj_t obj, char * key, uint64_t val);


/* Add new parameters to the JSON tree */

int pet_json_add_string(pet_json_obj_t obj, char * key, char * str);  
							                  
int pet_json_add_bool  (pet_json_obj_t obj, char * key, int      val);
int pet_json_add_int   (pet_json_obj_t obj, char * key, int      val);
int pet_json_add_double(pet_json_obj_t obj, char * key, double   val);
							                  
int pet_json_add_s8    (pet_json_obj_t obj, char * key, int8_t   val);
int pet_json_add_s16   (pet_json_obj_t obj, char * key, int16_t  val);
int pet_json_add_s32   (pet_json_obj_t obj, char * key, int32_t  val);
int pet_json_add_s64   (pet_json_obj_t obj, char * key, int64_t  val);
							                  
int pet_json_add_u8    (pet_json_obj_t obj, char * key, uint8_t  val);
int pet_json_add_u16   (pet_json_obj_t obj, char * key, uint16_t val);
int pet_json_add_u32   (pet_json_obj_t obj, char * key, uint32_t val);
int pet_json_add_u64   (pet_json_obj_t obj, char * key, uint64_t val);

/* Delete a parameter */
int pet_json_del_by_key(pet_json_obj_t obj, char * key);



/* 
 * Array Accessors 
 */

pet_json_obj_t pet_json_add_array(pet_json_obj_t obj, char * key);
pet_json_obj_t pet_json_get_array(pet_json_obj_t obj, char * key);
int            pet_json_del_array(pet_json_obj_t arr);

int            pet_json_get_array_len(pet_json_obj_t arr);


pet_json_obj_t pet_json_array_get_object(pet_json_obj_t arr, int   idx);
int            pet_json_array_add_object(pet_json_obj_t arr, int * idx, pet_json_obj_t obj);


/* 
 * Array Item Accessors
 */

/* Return a parameter directly from JSON
 * NOTE: Caller should not free these 
 */
int pet_json_array_get_string(pet_json_obj_t arr, int idx, char    ** val);

int pet_json_array_get_bool  (pet_json_obj_t arr, int idx, int      * val);
int pet_json_array_get_int   (pet_json_obj_t arr, int idx, int      * val);
int pet_json_array_get_double(pet_json_obj_t arr, int idx, double   * val);

int pet_json_array_get_s8    (pet_json_obj_t arr, int idx, int8_t   * val);
int pet_json_array_get_s16   (pet_json_obj_t arr, int idx, int16_t  * val);
int pet_json_array_get_s32   (pet_json_obj_t arr, int idx, int32_t  * val);
int pet_json_array_get_s64   (pet_json_obj_t arr, int idx, int64_t  * val);

int pet_json_array_get_u8    (pet_json_obj_t arr, int idx, uint8_t  * val);
int pet_json_array_get_u16   (pet_json_obj_t arr, int idx, uint16_t * val);
int pet_json_array_get_u32   (pet_json_obj_t arr, int idx, uint32_t * val);
int pet_json_array_get_u64   (pet_json_obj_t arr, int idx, uint64_t * val);

/* Set the value of an existing array item */

int pet_json_array_set_string(pet_json_obj_t arr, int idx, char     * val);

int pet_json_array_set_bool  (pet_json_obj_t arr, int idx, int        val);
int pet_json_array_set_int   (pet_json_obj_t arr, int idx, int        val);
int pet_json_array_set_double(pet_json_obj_t arr, int idx, double     val);

int pet_json_array_set_s8    (pet_json_obj_t arr, int idx, int8_t     val);
int pet_json_array_set_s16   (pet_json_obj_t arr, int idx, int16_t    val);
int pet_json_array_set_s32   (pet_json_obj_t arr, int idx, int32_t    val);
int pet_json_array_set_s64   (pet_json_obj_t arr, int idx, int64_t    val);

int pet_json_array_set_u8    (pet_json_obj_t arr, int idx, uint8_t    val);
int pet_json_array_set_u16   (pet_json_obj_t arr, int idx, uint16_t   val);
int pet_json_array_set_u32   (pet_json_obj_t arr, int idx, uint32_t   val);
int pet_json_array_set_u64   (pet_json_obj_t arr, int idx, uint64_t   val);

/* Add a new array item */

int pet_json_array_add_string(pet_json_obj_t arr, int * idx, char   * val);

int pet_json_array_add_bool  (pet_json_obj_t arr, int * idx, int      val);
int pet_json_array_add_int   (pet_json_obj_t arr, int * idx, int      val);
int pet_json_array_add_double(pet_json_obj_t arr, int * idx, double   val);

int pet_json_array_add_s8    (pet_json_obj_t arr, int * idx, int8_t   val);
int pet_json_array_add_s16   (pet_json_obj_t arr, int * idx, int16_t  val);
int pet_json_array_add_s32   (pet_json_obj_t arr, int * idx, int32_t  val);
int pet_json_array_add_s64   (pet_json_obj_t arr, int * idx, int64_t  val);

int pet_json_array_add_u8    (pet_json_obj_t arr, int * idx, uint8_t  val);
int pet_json_array_add_u16   (pet_json_obj_t arr, int * idx, uint16_t val);
int pet_json_array_add_u32   (pet_json_obj_t arr, int * idx, uint32_t val);
int pet_json_array_add_u64   (pet_json_obj_t arr, int * idx, uint64_t val);

/* Delete an array item */
int pet_json_array_del_idx   (pet_json_obj_t arr, int idx);
int pet_json_array_del_item  (pet_json_obj_t arr, pet_json_obj_t item);




/* Array iteration 
 * @iter: (pet_json_obj_t) - iterator variable
 * @arr:  (pet_json_obj_t) - array to iterate through
 */
#include "nxjson.h"
#define pet_json_arr_foreach(iter, arr)			\
	for ((iter) = ((struct nx_json *)(arr))->child; (iter) != NULL; (iter) = ((struct nx_json *)(iter))->next)

#ifdef __cplusplus
}
#endif
