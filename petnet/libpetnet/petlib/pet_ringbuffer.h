#ifndef __PET_RINGBUFFER_H__
#define __PET_RINGBUFFER_H__

/*
 * ringbuf.h - C ring buffer (FIFO) interface.
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


#include <stddef.h>
#include <sys/types.h>

/*
 * Create a new ring buffer with the given capacity.
 * Returns the new ring buffer object, or 0 if there's not enough
 * memory to fulfill the request for the given capacity.
 */
struct pet_ringbuf * pet_create_ringbuf(size_t capacity);


int pet_ringbuf_resize(struct pet_ringbuf * rb, size_t new_capacity);

void pet_free_ringbuf(struct pet_ringbuf * rb);
void pet_ringbuf_reset(struct pet_ringbuf * rb);

/*
 * Various capacity measures of the ring buffer, in bytes. 
 */
size_t pet_ringbuf_capacity(const struct pet_ringbuf * rb);
size_t pet_ringbuf_free_space(const struct pet_ringbuf * rb);
size_t pet_ringbuf_used_space(const struct pet_ringbuf * rb);

/* 
 * Binary state tests (1 = true, 0 = false)
 */
int pet_ringbuf_is_full(const struct pet_ringbuf * rb);
int pet_ringbuf_is_empty(const struct pet_ringbuf * rb);





/*
 * Read /count/ bytes from ringbuffer /rb/.
 * If dst is NULL, then data is dropped from the ringbuffer
 */
int pet_ringbuf_read(struct pet_ringbuf * rb, void * dst, size_t count);

/*
 * Write /count/ bytes into ring buffer /rb/. 
 */
int pet_ringbuf_write(struct pet_ringbuf * rb, void * src, size_t count);




#endif /* INCLUDED_RINGBUF_H */
