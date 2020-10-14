/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#include "checksum.h"




uint16_t
calculate_checksum(void     * data,
                   uint32_t   length_in_words)
{
    uint32_t   scratch   = 0;
    uint16_t * cast_data = data;

    uint32_t i = 0;

    for (i = 0; i < length_in_words; i++) {
        scratch += cast_data[i];

        // Wrap overflow
        if (scratch & 0xffff0000) {
            scratch &= 0x0000ffff;
            scratch += 1;
        }
    }

    return ~(uint16_t)scratch;
}


uint16_t
calculate_checksum_begin(void     * data,
                         uint32_t   length_in_words)
{
    uint32_t   scratch   = 0;
    uint16_t * cast_data = data;

    uint32_t i = 0;

    for (i = 0; i < length_in_words; i++) {
        scratch += cast_data[i];

        // Wrap overflow
        if (scratch & 0xffff0000) {
            scratch &= 0x0000ffff;
            scratch += 1;
        }
    }

    return (uint16_t)scratch;
}

uint16_t
calculate_checksum_continue(uint16_t   checksum,
                            void     * data,
                            uint32_t   length_in_words)
{
    uint32_t   scratch   = checksum;
    uint16_t * cast_data = data;

    uint32_t i = 0;

    for (i = 0; i < length_in_words; i++) {
        scratch += cast_data[i];

        // Wrap overflow
        if (scratch & 0xffff0000) {
            scratch &= 0x0000ffff;
            scratch += 1;
        }
    }

    return (uint16_t)scratch;
}

uint16_t
calculate_checksum_finalize(uint16_t   checksum,
                            void     * data,
                            uint32_t   length_in_words)
{
    uint32_t   scratch   = checksum;
    uint16_t * cast_data = data;

    uint32_t i = 0;

    for (i = 0; i < length_in_words; i++) {
        scratch += cast_data[i];

        // Wrap overflow
        if (scratch & 0xffff0000) {
            scratch &= 0x0000ffff;
            scratch += 1;
        }
    }

    return ~(uint16_t)scratch;
}
