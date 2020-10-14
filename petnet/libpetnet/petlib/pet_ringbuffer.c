/*
 * ringbuf.c - C ring buffer (FIFO) implementation.
 *
 * Written in 2011 by Drew Hess <dhess-src@bothan.net>.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "pet_util.h"
#include "pet_ringbuffer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/param.h>
#include <assert.h>

/*
 * The code is written for clarity, not cleverness or performance, and
 * contains many assert()s to enforce invariant assumptions and catch
 * bugs. Feel free to optimize the code and to remove asserts for use
 * in your own projects, once you're comfortable that it functions as
 * intended.
 */

struct pet_ringbuf {
    uint8_t * buf;
    uint8_t * head;
    uint8_t * tail;
    size_t    size;
};

struct pet_ringbuf *
pet_create_ringbuf(size_t capacity)
{
    struct pet_ringbuf * rb = pet_malloc(sizeof(struct pet_ringbuf));

    /* One byte is used for detecting the full condition. */
    rb->size = capacity + 1;
    rb->buf  = pet_malloc(rb->size);
    pet_ringbuf_reset(rb);

    return rb;
}


void
pet_ringbuf_reset(struct pet_ringbuf * rb)
{
    rb->head = rb->tail = rb->buf;
}

void
pet_free_ringbuf(struct pet_ringbuf * rb)
{
    pet_free(rb->buf);
    pet_free(rb);
}

size_t
pet_ringbuf_capacity(const struct pet_ringbuf * rb)
{
    return (rb->size - 1);
}

/*
 * Return a pointer to one-past-the-end of the ring buffer's
 * contiguous buffer. You shouldn't normally need to use this function
 * unless you're writing a new ringbuf_* function.
 */
static const uint8_t *
__end_ptr(const struct pet_ringbuf * rb)
{
    return (rb->buf + rb->size);
}

#if 0
/*
 * Given a ring buffer rb and a pointer to a location within its
 * contiguous buffer, return the a pointer to the next logical
 * location in the ring buffer.
 */
static uint8_t *
__next_ptr(struct pet_ringbuf * rb, 
              const uint8_t      * p)
{
    return rb->buf + ((++p - rb->buf) % rb->size);
}
#endif

size_t
pet_ringbuf_free_space(const struct pet_ringbuf * rb)
{
    if (rb->head >= rb->tail) {
        return (pet_ringbuf_capacity(rb) - (rb->head - rb->tail));
    } else {
        return (rb->tail - rb->head - 1);
    }
}

size_t
pet_ringbuf_used_space(const struct pet_ringbuf * rb)
{
    return (pet_ringbuf_capacity(rb) - pet_ringbuf_free_space(rb));
}

int
pet_ringbuf_is_full(const struct pet_ringbuf * rb)
{
    return (pet_ringbuf_free_space(rb) == 0);
}

int
pet_ringbuf_is_empty(const struct pet_ringbuf * rb)
{
    return (pet_ringbuf_free_space(rb) == pet_ringbuf_capacity(rb));
}






int
pet_ringbuf_write(struct pet_ringbuf * rb, 
                  void               * src, 
                  size_t               count)
{
    size_t nwritten = 0;

    count = MIN(count, pet_ringbuf_free_space(rb));

    while (nwritten != count) {
        /* don't copy beyond the end of the buffer */
        size_t n = MIN(__end_ptr(rb) - rb->head, count - nwritten);

        memcpy(rb->head, src + nwritten, n);

        rb->head += n;
        nwritten += n;

        if (rb->head == __end_ptr(rb)) {
            rb->head = rb->buf;
        }
    }

    return nwritten;
}


int 
pet_ringbuf_read(struct pet_ringbuf * rb, 
                 void               * dst, 
                 size_t               count)
{
    size_t nread = 0;

    count = MIN(count, pet_ringbuf_used_space(rb));

    while (nread != count) {
        size_t n = MIN(__end_ptr(rb) - rb->tail, count - nread);

        if (dst) {
            memcpy(dst + nread, rb->tail, n);
        }

        rb->tail += n;
        nread    += n;

        if (rb->tail == __end_ptr(rb)) {
            rb->tail = rb->buf;
        }
    }

    return nread;
}



static int
__ringbuf_move(struct pet_ringbuf * src, 
               struct pet_ringbuf * dst)
{
    size_t bytes_to_move = pet_ringbuf_used_space(src);
    size_t bytes_moved   = 0;
    
    if (bytes_to_move > pet_ringbuf_free_space(dst)) {
        return -1;
    }
    

    while (bytes_moved != bytes_to_move) {
        size_t nsrc = MIN(__end_ptr(src) - src->tail, bytes_to_move - bytes_moved);
        size_t n    = MIN(__end_ptr(dst) - dst->head, nsrc);

        memcpy(dst->head, src->tail, n);

        src->tail   += n;
        dst->head   += n;
        bytes_moved += n;

        if (src->tail == __end_ptr(src)) {
            src->tail = src->buf;
        }
        
        if (dst->head == __end_ptr(dst)) {
            dst->head = dst->buf;
        }
    }

    return 0;
}


int 
pet_ringbuf_resize(struct pet_ringbuf * rb, 
                   size_t               new_capacity)
{
    struct pet_ringbuf * tmp_rb = NULL;
    
    if (pet_ringbuf_used_space(rb) > new_capacity) {
        return -1;
    }

    tmp_rb = pet_create_ringbuf(new_capacity);

    __ringbuf_move(rb, tmp_rb);
    
    pet_free(rb->buf);

    rb->buf  = tmp_rb->buf;
    rb->head = tmp_rb->head;
    rb->tail = tmp_rb->tail;

    pet_free(tmp_rb);

    return 0;

}