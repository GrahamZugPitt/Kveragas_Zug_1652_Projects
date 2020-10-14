/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#ifndef __TIMER_H__
#define __TIMER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


/* struct pet_timeout is an opaque structure, and simply acts as a handle for either demuxing or cancelling the timer */

struct pet_timeout;

typedef void (*pet_timeout_callback_fn)(struct pet_timeout *, void * arg);

/* 
 * Create a timeout that will expire in /num_secs/ seconds
 * 
 * /callback_fn/ will be called when timeout expires (if it hasn't been cancelled)
 * /cb_arg/ will be passed as /arg/ parameter in /callback_fn/
 * 
 * NOTE: The return value is a handle to a timeout object, but is otherwise opaque
 *       It is only returned so that it can be used to cancel the timeout if needed
 *          (see pet_cancel_timeout())
 */
struct pet_timeout * pet_add_timeout(int num_secs, 
                                     pet_timeout_callback_fn callback_fn, 
                                     void * cb_arg);


/* 
 * Cancel a pending timeout
 * 
 * The /timeout/ argument is the pointer that was returned when the timeout was created using pet_add_timeout()
 * 
 * Returns 1 on success, or 0 on failure
 *   Failure can occur due to either an invalid /timeout/ handle, or if the timeout was in the process of
 *   being fired when the cancel attempt was made
 * 
 * IMPORTANT: You must be very careful with timeout cancellation concurrency. Timeouts are freed after 
 * they are fired, so you must make sure that the timer handler is not invoked before you cancel the timeout
 * The best way of doing this is using a mutex and a 'timed_out' flag in the data object that the timeout is 
 * associated with. The mutex should be acquired inside the timeout callback function and before making the
 * cancel request. The timeout callback should set the timed_out flag, and the flag should be checked before 
 * attempting to cancel the timeout. 
 * 
 * On a related note, you'll need to be careful with reference counting the objects being timed out as well.
 * If you free an object that has a timeout pending, then you're going to have a bad time. 
 * 
 * Example:
 * 
 * void timeout_callback(struct pet_timeout * timeout, void * arg) {
 *      struct my_obj * obj = arg;
 * 
 *      LOCK(obj->lock);
 *      obj->timed_out = 1;
 *      UNLOCK(obj->lock);
 * }
 * 
 * some_other_func(struct my_obj * obj) {
 *      ....
 *      LOCK(obj->lock);
 *      if (obj->timed_out == 0) {
 *          pet_cancel_timeout(obj->timeout);
 *      }
 *      UNLOCK(obj->lock);
 *      ...
 * }
 */
int pet_cancel_timeout(struct pet_timeout  * timeout);

int pet_timer_init();

#ifdef __cplusplus
}
#endif

#endif