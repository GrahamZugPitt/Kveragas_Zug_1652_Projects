/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __PACKET_POOL_H__
#define __PACKET_POOL_H__

#ifdef __cplusplus
extern "C" {
#endif

struct petnet;

int
pkt_pool_init(struct petnet * state);



struct packet * pkt_pool_get(struct petnet * state);

void 
pkt_pool_put(struct petnet * state,
             struct packet * pkt);

#ifdef __cplusplus
}
#endif

#endif