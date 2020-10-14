/* 
 * Copyright (c) 2019, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <assert.h>


#include <petnet.h>
#include <core/packet.h>

#include "pet_driver.h"

extern struct petnet * petnet_state;


int 
pet_driver_tx(struct packet * pkt)
{
    int ret = 0;

    assert(petnet_state->driver->tx != NULL);

    ret = petnet_state->driver->tx(pkt);

    free_packet(pkt);

    return ret;
}
