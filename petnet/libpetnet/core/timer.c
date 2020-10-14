/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>


#include <petnet.h>


#include "timer.h"

#include <petlib/pet_heap.h>
#include <petlib/pet_util.h>
#include <petlib/pet_log.h>



struct petnet_timer_state {
    struct pet_heap * timer_heap;

    struct sigevent timer_evt; 
    timer_t sys_timer;

    struct timespec current_deadline;

    pthread_mutex_t timer_lock;
};

struct pet_timeout {
    struct petnet_timer_state * timer_state; // backreference to global timer state

    pet_timeout_callback_fn callback_fn;
    void * cb_arg;

    struct timespec deadline;

    struct {
        uint8_t cancelled : 1;
        uint8_t fired     : 1;
    } __attribute__((packed));
};


static void 
__free_timeout(struct pet_timeout * timeout)
{
    pet_free(timeout);
}

void
pet_retire_timeout(struct pet_timeout * timeout)
{
    if (timeout->fired == 0) {
        log_error("Cannot reap an unfired timeout. You must cancel it instead.");
        return;
    }

    __free_timeout(timeout);
}

int
pet_cancel_timeout(struct pet_timeout * timeout)
{
    struct petnet_timer_state * timer_state = NULL;
    int cancelled = 0;

    if (timeout == NULL) {
        return 0;
    }

    timer_state = timeout->timer_state;

    pthread_mutex_lock(&(timer_state->timer_lock));
    {
        if (timeout->fired == 0) {
            timeout->cancelled = 1;
            cancelled          = 1;
        }
    }
    pthread_mutex_unlock(&(timer_state->timer_lock));

    return cancelled;
}

static inline void 
timespec_diff(struct timespec * a, 
              struct timespec * b,
              struct timespec * result) {

    result->tv_sec  = a->tv_sec  - b->tv_sec;
    result->tv_nsec = a->tv_nsec - b->tv_nsec;

    if (result->tv_nsec < 0) {
        --result->tv_sec;
        result->tv_nsec += 1000000000L;
    }
}

static int 
timespec_cmp(struct timespec * ts1,
             struct timespec * ts2)
{
    int ret = 0;

    if (ts1->tv_sec == ts2->tv_sec) {
        if (ts1->tv_nsec == ts2->tv_nsec) {
            ret = 0;
        } else {
            ret = (ts1->tv_nsec > ts2->tv_nsec) ? 1 : -1;
        }
    } else {
            ret = (ts1->tv_sec  > ts2->tv_sec)  ? 1 : -1;
    }
    /*   pet_printf("Comparing TS1 (%lld.%.9ld) to TS2 (%lld.%.9ld) = %d\n", 
                (long long)ts1->tv_sec, ts1->tv_nsec,
                (long long)ts2->tv_sec, ts2->tv_nsec, ret);
    */
    return ret;
}

static int 
__timer_cmp_fn(void * key1, 
               void * key2) 
{
    return timespec_cmp(key1, key2);
}

static int
__reset_timer_locked(struct petnet_timer_state * timer_state)
{
    void               * timeout_key = NULL;
    struct pet_timeout * timeout     = NULL;
    struct itimerspec    sys_timeout;

    int ret = 0;

    memset(&sys_timeout, 0, sizeof(struct itimerspec));

    ret = pet_heap_peek(timer_state->timer_heap, &timeout_key, (void **)&timeout);

    if (ret != 0) {
        return -1;
    }

    if (timespec_cmp(&(timer_state->current_deadline), &(timeout->deadline)) == 0) {
        return 0;
    }

    timer_state->current_deadline = timeout->deadline;
    sys_timeout.it_value          = timeout->deadline;

    //  pet_printf("Setting timer for (%lld.%.9ld)\n", (long long)timeout->deadline.tv_sec, timeout->deadline.tv_nsec);

    ret = timer_settime(timer_state->sys_timer, TIMER_ABSTIME, &sys_timeout, NULL);

    if (ret != 0) {
        log_error("Could not reset system timer\n");
        return -1;
    }

    return 0;
}

static int 
__reset_timer()
{
    struct petnet_timer_state * timer_state = petnet_state->timers;
    int ret = 0;

    pthread_mutex_lock(&(timer_state->timer_lock));
    {
        ret = __reset_timer_locked(timer_state);
    }
    pthread_mutex_unlock(&(timer_state->timer_lock));

    if (ret == -1) {
        return -1;
    }

    return 0;
}

static void
__timer_handler(union sigval sv)
{
    struct petnet             * net_state   = (struct petnet *)sv.sival_ptr;
    struct petnet_timer_state * timer_state = petnet_state->timers;

    struct timespec      current_time = {0, 0};
    void               * timeout_key  = NULL;
    struct pet_timeout * timeout      = NULL;

    int ret = 0;

    ret = clock_gettime(CLOCK_MONOTONIC, &current_time);

    if (ret != 0) {
        log_error("Could not get current time\n");
        goto out;
    }

    while (1) {
        int valid_timeout = 0;

        pthread_mutex_lock(&(timer_state->timer_lock));
        {
            ret = pet_heap_peek(timer_state->timer_heap, &timeout_key, (void **)&timeout);

            if ((ret == 0) && 
                (timespec_cmp(&(current_time), &(timeout->deadline)) > 0)) {
                ret = pet_heap_pop(timer_state->timer_heap, &timeout_key, (void **)&timeout);
                valid_timeout  = 1;
                timeout->fired = 1;
            } 
        }
        pthread_mutex_unlock(&(timer_state->timer_lock));

        if (valid_timeout == 0) {
            break;
        }

        if (ret != 0) {
            log_error("Failed to Pop timeout out of timer heap\n");
            break;
        }


        if (timeout->cancelled) {
            /* This timeout has been cancelled so just ignore it. */
            __free_timeout(timeout);
            continue;
        }

        //  pet_printf("Handling timeout set for (%lld.%.9ld)\n", (long long)timeout->deadline.tv_sec, timeout->deadline.tv_nsec);


        timeout->callback_fn(timeout, timeout->cb_arg);

        __free_timeout(timeout);
    }

out:
    __reset_timer(net_state);
}




struct pet_timeout * 
pet_add_timeout(int num_secs, 
                pet_timeout_callback_fn callback_fn, 
                void * cb_arg)
{
    struct petnet_timer_state * timer_state = petnet_state->timers;

    struct timespec      current_time = {0, 0};
    struct pet_timeout * timeout      = NULL;

    int ret = 0;

    //  log_error("Adding timeout (secs=%d)\n", num_secs);

    ret = clock_gettime(CLOCK_MONOTONIC, &current_time);

    if (ret != 0) {
        log_error("Could not get the current time\n");
        goto err;
    }

    current_time.tv_sec += num_secs;

    //  pet_printf("Adding timeout at (%lld.%.9ld)\n", (long long)current_time.tv_sec, current_time.tv_nsec);

    timeout = pet_malloc(sizeof(struct pet_timeout));
    timeout->callback_fn  = callback_fn;
    timeout->cancelled    = 0;
    timeout->fired        = 0;
    timeout->cb_arg       = cb_arg;
    timeout->deadline     = current_time;
    timeout->timer_state  = timer_state;

    pthread_mutex_lock(&(timer_state->timer_lock));
    {
        ret = pet_heap_insert(timer_state->timer_heap, &(timeout->deadline), timeout);
    }
    pthread_mutex_unlock(&(timer_state->timer_lock));

    if (ret != 0) {
        log_error("Could not insert timeout into timer heap\n");
        goto err;
    }

    __reset_timer();

    return timeout;
err:

    if (timeout) __free_timeout(timeout);

    return NULL;
}

int
pet_timer_init(struct petnet * petnet_state)
{
    struct petnet_timer_state * timer_state = NULL;
    int ret = 0;

    timer_state = pet_malloc(sizeof(struct petnet_timer_state));

    timer_state->timer_heap = pet_heap_create(0, __timer_cmp_fn);
    pthread_mutex_init(&(timer_state->timer_lock), NULL);

    timer_state->timer_evt.sigev_notify            = SIGEV_THREAD;
    timer_state->timer_evt.sigev_notify_function   = __timer_handler;
    timer_state->timer_evt.sigev_value.sival_ptr   = petnet_state;
    timer_state->timer_evt.sigev_notify_attributes = NULL;
    ret = timer_create(CLOCK_MONOTONIC, &(timer_state->timer_evt), &(timer_state->sys_timer));

    if (ret != 0) {
        log_error("Could not create timer (%d: %s)\n", errno, strerror(errno));
        goto err;
    }

    petnet_state->timers = timer_state;

    return 0;

err:
    return -1;
}


#if 0
struct sigevent timer_signal_event;
timer_t timer;

struct itimerspec timer_period;

printf("Create timer\n");
timer_signal_event.sigev_notify = SIGEV_THREAD;
timer_signal_event.sigev_notify_function = Timer_has_expired;       // This function will be called when timer expires
// Note that the following is a union. Assign one or the other (preferably by pointer)
//timer_signal_event.sigev_value.sival_int = 38;                        // This argument will be passed to the function
timer_signal_event.sigev_value.sival_ptr = (void *) &pass_value_by_pointer;     // as will this (both in a structure)
timer_signal_event.sigev_notify_attributes = NULL;
timer_create(CLOCK_MONOTONIC, &timer_signal_event, &timer);

printf("Start timer\n");
timer_period.it_value.tv_sec = 1;                                   // 1 second timer
timer_period.it_value.tv_nsec = 0;                                  // no nano-seconds
timer_period.it_interval.tv_sec = 0;                                // non-repeating timer
timer_period.it_interval.tv_nsec = 0;

timer_settime(timer, 0, &timer_period, NULL);
sleep(2);

printf("----------------------------\n");
printf("Start timer a second time\n");
timer_settime(timer, 0, &timer_period, NULL);
sleep(2);

#endif