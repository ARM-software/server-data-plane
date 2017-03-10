/* Copyright (c) 2017, ARM Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 * 
 * ODP Chained Buffer
 */

/* Helper functions to define a chained buffer interface since
 * current ODP code does not have a working implementation.
 */

#ifndef ODP_CHAINED_BUFFER_H_
#define ODP_CHAINED_BUFFER_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/buffer.h>
#include <odp/api/pool.h>

/**
 * ASSUMPTIONS: A chained buffer will be composed of all the same segment
 *              size.  This allows more efficient copying 
 */

/* Allocate a buffer that will potentially be chained
 * pool_hdl -- pool to alloc from
 * total_size -- total number of user accessible bytes to create
 *
 * return -- handle to odp_buffer_t
 */
odp_buffer_t odp_chained_buffer_alloc(odp_pool_t pool_hdl,
				      size_t total_size);

void odp_chained_buffer_free(odp_buffer_t buf);

/* Copy bytes from a buffer into a chained buffer
 * cbuf -- buffer handle
 * offset -- offset into chained buffer
 * ibuf -- input buffer
 * size -- number of bytes to copy
 *
 * return -- 0 on success, -1 on error
 */
int odp_chained_buffer_copyin(odp_buffer_t cbuf, int offset,
                              const uint8_t* ibuf, size_t size);

/* Copy bytes from chained buffer into specified buffer
 * cbuf -- buffer handle
 * offset -- offset into chained buffer to start copying from
 * obuf -- buffer to copy into
 * size -- number of bytes to copy
 *
 * return -- 0 on success, -1 on error
 */
int odp_chained_buffer_copyout(odp_buffer_t cbuf, int offset,
                               uint8_t *obuf, size_t size);

/* Copy payload bytes from one chained buffer to another
 * cbuf1 -- dest buffer
 * offset1 -- offset into chained dest buffer
 * cbuf2 -- src buffer
 * offset2 -- offset into chained src buffer
 * size -- number of bytes to copy
 *
 * return -- 0 on success, -1 on error
 */
int odp_chained_buffer_copydata(odp_buffer_t cbuf_dest, int offset_dest,
                                odp_buffer_t cbuf_src, int offset_src, 
				size_t size);

/* Test if the buffer is a chained buffer
 * buf -- buffer handle
 *
 * return -- 1 if it is a chained buffer, 0 if not
 */
int odp_is_chained_buffer(odp_buffer_t buf);

/* Get the size of the chained buffer as amount of allocated data
 * buf -- buffer handle
 *
 * return -- number of bytes in the buffer, returns -1 on error
 */
size_t odp_sizeof_chained_buffer(odp_buffer_t buf);

/* Append a fragment to a chained buffer (no scatter list) -- somewhat expensive as this
 * will merge the buffers to maintain the assumption that the data is
 * packed.
 * src_buf -- handle to the buffer we are going to splice in (can be any size)
 * size -- size of the data contained in the buffer
 * dest_buf -- handle of buffer we are splicing into
 * offset -- offset to start copying in data/splicing.
 * 
 * return -- number of bytes copied, returns -1 on error
 */
int odp_append_fragment_to_chained_buffer(odp_buffer_t src_buf, size_t size,
                                          odp_buffer_t dest_buf, int offset);

/* Trim fragments from the front of a chained buffer.  Only trim in multiples
 * of the scatter gather array for simplicity's sake.
 *
 * inbuf -- input chained buffer
 * offset -- offset to trim to if we can
 * trimmed_offset -- offset we trimmed to
 *
 * return -- odp_buffer_t handle, -1 on error
 */
odp_buffer_t odp_trim_chained_buffer(odp_buffer_t inbuf, int offset,
				     int *trimmed_offset);


#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif
