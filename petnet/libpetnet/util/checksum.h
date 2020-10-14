/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* 
 * IMPORTANT! IMPORTANT! IMPORTANT!
 * 
 * The checksum calculations here assume that the data is in 16 bit units
 * 
 * This means that if you have an odd number of bytes you need to caculate a checksum over, then
 *    you will need to add a single 0 byte value to pad out to 16 bits
 */ 

/* 
 * Simple checksum calculation over a single buffer
 * 
 * Returns a checksum value that can be added directly to a packet header
 */
uint16_t 
calculate_checksum(void     * data,
                   uint32_t   length_in_words);


/* 
 * Same as calculating the checksum, 
 * but the semantics of the operation are different so we provide a separate call point 
 */
static inline uint16_t
verify_checksum(void     * data,
                uint32_t   length_in_words)
{
    return calculate_checksum(data, length_in_words);
}



/* 
 * Multi-stage checksum calculation over multiple buffers
 * 
 * Pass the first buffer to calculate_checksum_begin()
 * Pass intermediate buffers to calculate_checksum_continue()
 * Pass the final buffer (or a NULL buffer) to calculate_checksum_finalize()
 * 
 * calculate_checksum_begin() and calculate_checksum_continue() return intermediate checksum 
 *      values, that must be passed into subsequent calls as the /checksum/ argument
 * 
 * calculate_checksum_finalize() returns a checksum value that can be added directly to a packet header
 */
uint16_t
calculate_checksum_begin(void     * data,
                         uint32_t   length_in_words);


uint16_t
calculate_checksum_continue(uint16_t   checksum,
                            void     * data,
                            uint32_t   length_in_words);


uint16_t
calculate_checksum_finalize(uint16_t   checksum,
                            void     * data,
                            uint32_t   length_in_words);




/* Same as calculating the checksum, 
 * but the semantics of the operation are different so we provide a separate call point 
 */
static inline uint16_t
verify_checksum_begin(void     * data,
                      uint32_t   length_in_words)
{
    return calculate_checksum_begin(data, length_in_words);
}

static inline uint16_t
verify_checksum_continue(uint16_t   checksum,
                         void     * data,
                         uint32_t   length_in_words)
{
    return calculate_checksum_continue(checksum, data, length_in_words);
}

static inline uint16_t
verify_checksum_finalize(uint16_t   checksum,
                         void     * data,
                         uint32_t   length_in_words)
{
    return calculate_checksum_finalize(checksum, data, length_in_words);
}



#ifdef __cplusplus
}
#endif

#endif