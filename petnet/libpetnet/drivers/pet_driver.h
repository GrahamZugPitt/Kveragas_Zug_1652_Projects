/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __PET_DRIVER_H__
#define __PET_DRIVER_H__

#ifdef __cplusplus
extern "C" {
#endif

struct petnet;
struct packet;

/* This must be the first member of any driver state structure */
struct petnet_driver {
	int (*tx)(struct packet * pkt);
	int (*listen)();


	int (*rx)();
	int (*poll)();
};


int pet_driver_tx(struct packet * pkt);


int tap_driver_init(struct petnet * petnet_state);


#ifdef __cplusplus
}
#endif

#endif