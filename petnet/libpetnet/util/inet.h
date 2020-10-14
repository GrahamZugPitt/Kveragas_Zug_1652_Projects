/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */	

#ifndef __INET_H__
#define __INET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

static inline uint32_t 
htonl(uint32_t host_u32)
{
    return  ((host_u32 & 0x000000ff) << 24) | 
            ((host_u32 & 0x0000ff00) << 8)  | 
            ((host_u32 & 0x00ff0000) >> 8)  | 
            ((host_u32 & 0xff000000) >> 24);
}


static inline uint16_t 
htons(uint16_t host_u16)
{
    return  ((host_u16 & 0x00ff) << 8)  | 
            ((host_u16 & 0xff00) >> 8);
}

static inline uint32_t 
ntohl(uint32_t net_u32)
{
    return  ((net_u32 & 0x000000ff) << 24) | 
            ((net_u32 & 0x0000ff00) << 8)  | 
            ((net_u32 & 0x00ff0000) >> 8)  | 
            ((net_u32 & 0xff000000) >> 24);
}

static inline uint16_t
ntohs(uint16_t net_u16)
{
    return  ((net_u16 & 0x00ff) << 8)  | 
            ((net_u16 & 0xff00) >> 8);

}






#ifdef __cplusplus
}
#endif

#endif