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

#include <odp/api/chained_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>

#include <assert.h>
#include <string.h>

#define odp_min(a, b) (a <= b) ? a : b

odp_buffer_t odp_chained_buffer_alloc(odp_pool_t pool_hdl, size_t total_size)
{
	odp_buffer_t buf;
	odp_buffer_t next_buf;
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *next_hdr;
	odp_buffer_hdr_t *segs;
	pool_entry_t *pool_entry;
	size_t chunk_size;
	size_t size_needed = total_size;
	int num_chunks;
	int num_nodes;
	int num_chunks_allocated;
	size_t max_buf_size;
	int i; /*,j;*/

	// Get the sizes of the buffers being allocated and how many we will
	// need and how many scatter lists we need to chain together.
	pool_entry = get_pool_entry(pool_handle_to_index(pool_hdl));
	chunk_size = pool_entry->s.seg_size;
	max_buf_size = pool_entry->s.seg_size * ODP_BUFFER_MAX_SEG;
	num_chunks = (total_size % chunk_size) ? (total_size / chunk_size) + 1
					       : total_size / chunk_size;
	num_nodes = (num_chunks % ODP_BUFFER_MAX_SEG)
			? (num_chunks / ODP_BUFFER_MAX_SEG) + 1
			: num_chunks / ODP_BUFFER_MAX_SEG;
	num_chunks_allocated = 0;

	/* Let ODP allocate segments for me */
	buf =
	    odp_buffer_alloc_size(pool_hdl, odp_min(max_buf_size, size_needed));
	if (odp_unlikely(!odp_buffer_is_valid(buf)))
		return ODP_BUFFER_INVALID;

	hdr = odp_buf_to_hdr(buf);
	hdr->num_segnodes = num_nodes;
	segs = hdr;
	size_needed -= odp_min(max_buf_size, size_needed);
	num_chunks_allocated += segs->segcount;
	segs->seg_list_pos = 0;

	// Allocate the buffers for each linked scatter list
	for (i = 1; i < num_nodes; i++) {
		// Set up the linking if the scatter list is full, otherwise
		// do nothing as we're done.
		if (segs->addr[ODP_BUFFER_MAX_SEG - 1] != NULL) {
			next_buf = odp_buffer_alloc_size(
			    pool_hdl, odp_min(max_buf_size, size_needed));

			if (odp_unlikely(!odp_buffer_is_valid(next_buf))) {
				// Circularize the buffer and then fail
				segs->next_segs = hdr;
				hdr->prev_segs = segs;
				goto fail_cleanup;
			}
			next_hdr = odp_buf_to_hdr(next_buf);
			segs->next_segs = next_hdr;
			segs->next_segs->prev_segs = segs;
			segs = segs->next_segs;
			size_needed -= odp_min(max_buf_size, size_needed);
			num_chunks_allocated += segs->segcount;
			segs->seg_list_pos = i;
		} else {
			assert(0);
		}
	}

	// Complete circular linked list construction
	hdr->prev_segs = segs;
	segs->next_segs = hdr;
	hdr->size = num_chunks_allocated * pool_entry->s.seg_size;

	hdr->flags.zeroized = pool_entry->s.flags.zeroized;

	return buf;

fail_cleanup:
	odp_chained_buffer_free(buf);
	return ODP_BUFFER_INVALID;
}

void odp_chained_buffer_free(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *segs;
	odp_buffer_hdr_t *segs_prev;
	odp_buffer_hdr_t *tmp;

	hdr = odp_buf_to_hdr(buf);
	if (hdr == NULL)
		return;

	if (!odp_is_chained_buffer(buf))
		goto cleanup;

	// Setup pointers
	segs = hdr;
	segs_prev = hdr->prev_segs;

	// Reverse traverse the linked list
	while (segs_prev != segs) {
		tmp = segs_prev;
		segs_prev = segs_prev->prev_segs;
		// takes care of deallocating segments
		tmp->next_segs = NULL;
		tmp->prev_segs = NULL;
		tmp->seg_list_pos = 0;
		tmp->num_segnodes = 0;
		_buffer_free(tmp->handle.handle);
	}

cleanup:
	// Reset to size to normal
	hdr->size = hdr->segcount * hdr->segsize;
	// De-allocate the original buffer
	_buffer_free(buf);
}

int odp_chained_buffer_copyin(odp_buffer_t cbuf, int offset,
			      const uint8_t *ibuf, size_t size)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *segs;
	uint8_t *mapaddr = NULL;
	uint32_t seglen = 0;
	int seg_node_index = 0;
	uint32_t tocpy;
	uint32_t cpylen;
	uint32_t curoff;

	size_t buf_size;
	size_t segment_size;
	int i;

	// Is the buffer valid?
	hdr = odp_buf_to_hdr(cbuf);
	if (hdr == NULL)
		return -1;

	buf_size = odp_sizeof_chained_buffer(cbuf);
	segment_size = hdr->segsize * ODP_BUFFER_MAX_SEG;

	// Check if we can copy over all the data, if not, return error
	if (offset + size > buf_size)
		return -1;

	tocpy = size;
	curoff = offset;

	// Move ourselves to the segment node that contains
	// our start position
	seg_node_index = curoff / segment_size;
	segs = hdr;
	for (i = 0; i < seg_node_index; i++) {
		segs = segs->next_segs;
	}
	// Update cur_offset to be in the correct location for our segment
	curoff -= seg_node_index * segment_size;

	// Loop through linked list of scatter/gather lists
	while (tocpy) {
		mapaddr =
		    (uint8_t *)buffer_map(segs, curoff, &seglen, segs->size);
		cpylen = tocpy > seglen ? seglen : tocpy;

		assert(cpylen + curoff <= segs->size);
		assert((curoff % segs->segsize) + cpylen <= segs->segsize);

		memcpy(mapaddr, ibuf, cpylen);
		curoff += cpylen;
		ibuf += cpylen;
		tocpy -= cpylen;

		if (!(curoff % segment_size)) {
			curoff = 0;
			segs = segs->next_segs;
		}
	}

	return 0;
}

// TODO: These two functions could be combined somewhat...
int odp_chained_buffer_copyout(odp_buffer_t cbuf, int offset, uint8_t *obuf,
			       size_t size)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *segs;
	uint8_t *mapaddr = NULL;
	uint32_t seglen = 0;
	int seg_node_index = 0;
	uint32_t tocpy;
	uint32_t cpylen;
	uint32_t curoff;

	size_t buf_size;
	size_t segment_size;
	int i;

	// Is the buffer valid?
	hdr = odp_buf_to_hdr(cbuf);
	if (hdr == NULL)
		return -1;

	buf_size = odp_sizeof_chained_buffer(cbuf);
	segment_size = hdr->segsize * ODP_BUFFER_MAX_SEG;

	// Check if we can copy over all the data, if not, return error
	if (offset + size > buf_size)
		return -1;

	tocpy = size;
	curoff = offset;

	// Move ourselves to the segment node that contains
	// our start position
	seg_node_index = curoff / segment_size;
	segs = hdr;
	for (i = 0; i < seg_node_index; i++) {
		segs = segs->next_segs;
	}
	// Update cur_offset to be in the correct location for our segment
	curoff -= seg_node_index * segment_size;

	// Loop through linked list of scatter/gather lists
	while (tocpy) {
		mapaddr =
		    (uint8_t *)buffer_map(segs, curoff, &seglen, segs->size);
		cpylen = tocpy > seglen ? seglen : tocpy;

		assert(cpylen + curoff <= segs->size);
		assert((curoff % segs->segsize) + cpylen <= segs->segsize);

		memcpy(obuf, mapaddr, cpylen);
		curoff += cpylen;
		obuf += cpylen;
		tocpy -= cpylen;

		if (!(curoff % segment_size)) {
			curoff = 0;
			segs = segs->next_segs;
		}
	}

	return 0;
}

int odp_chained_buffer_copydata(odp_buffer_t cbuf_dest, int offset_dest,
				odp_buffer_t cbuf_src, int offset_src,
				size_t size)
{
	odp_buffer_hdr_t *dsthdr;
	odp_buffer_hdr_t *dstsegs;
	odp_buffer_hdr_t *srchdr;
	odp_buffer_hdr_t *srcsegs;
	uint8_t *dstmapaddr = NULL;
	uint8_t *srcmapaddr = NULL;
	uint32_t dstsegment_size = 0;
	uint32_t srcsegment_size = 0;
	uint32_t dstseglen = 0;
	uint32_t srcseglen = 0;
	int dst_segnode_idx = 0;
	int src_segnode_idx = 0;
	uint32_t tocpy;
	uint32_t cpylen;
	uint32_t minseg;
	uint32_t dstcuroff;
	uint32_t srccuroff;

	// Is the buffer valid?
	dsthdr = odp_buf_to_hdr(cbuf_dest);
	srchdr = odp_buf_to_hdr(cbuf_src);

	size_t buf_size = odp_sizeof_chained_buffer(cbuf_dest);
	int i;

	// Check if we can copy over all the data, if not, return error
	if (offset_dest + size > buf_size) {
		ODP_ERR("offset: %d size: %d buf_size: %d\n", offset_dest, size, buf_size);
		assert(0);
		return -1;
	}
	if (offset_src + size > odp_sizeof_chained_buffer(cbuf_src)) {
		assert(0);
		return -1;
	}

	if (dsthdr == NULL || srchdr == NULL) {
		assert(0);
		return -1;
	}

	tocpy = size;
	dstcuroff = offset_dest;
	srccuroff = offset_src;
	dstsegment_size = dsthdr->segsize * ODP_BUFFER_MAX_SEG;
	srcsegment_size = srchdr->segsize * ODP_BUFFER_MAX_SEG;

	// Move ourselves to the segment node that contains
	// our start position
	dst_segnode_idx = dstcuroff / dstsegment_size;
	dstsegs = dsthdr;
	for (i = 0; i < dst_segnode_idx; i++) {
		dstsegs = dstsegs->next_segs;
	}
	// Update cur_offset to be in the correct location for our segment
	dstcuroff -= dst_segnode_idx * dstsegment_size;

	src_segnode_idx = srccuroff / srcsegment_size;
	srcsegs = srchdr;
	for (i = 0; i < src_segnode_idx; i++) {
		srcsegs = srcsegs->next_segs;
	}
	srccuroff -= src_segnode_idx * srcsegment_size;

	// Loop through linked list of scatter/gather lists
	while (tocpy) {
		dstmapaddr = (uint8_t *)buffer_map(dstsegs, dstcuroff,
						   &dstseglen, dstsegs->size);
		srcmapaddr = (uint8_t *)buffer_map(srcsegs, srccuroff,
						   &srcseglen, srcsegs->size);
		minseg = dstseglen > srcseglen ? srcseglen : dstseglen;

		cpylen = tocpy > minseg ? minseg : tocpy;

		assert(cpylen + dstcuroff <= dstsegs->size);
		assert(cpylen + srccuroff <= srcsegs->size);
		assert((dstcuroff % dstsegs->segsize) + cpylen <=
		       dstsegs->segsize);
		assert((srccuroff % srcsegs->segsize) + cpylen <=
		       srcsegs->segsize);

		memcpy(dstmapaddr, srcmapaddr, cpylen);

		srccuroff += cpylen;
		dstcuroff += cpylen;
		tocpy -= cpylen;

		if (!(srccuroff % srcsegment_size)) {
			srccuroff = 0;
			srcsegs = srcsegs->next_segs;
		}
		if (!(dstcuroff % dstsegment_size)) {
			dstcuroff = 0;
			dstsegs = dstsegs->next_segs;
		}
	}

	return 0;
}

int odp_is_chained_buffer(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;

	hdr = odp_buf_to_hdr(buf);
	if (hdr == NULL)
		return 0;

	// Num segnodes only gets populated if
	// allocated by the chained buffer code
	if (hdr->num_segnodes || hdr->next_segs != NULL ||
	    hdr->prev_segs != NULL) {
		return 1;
	}

	return 0;
}

size_t odp_sizeof_chained_buffer(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;

	hdr = odp_buf_to_hdr(buf);
	if (hdr == NULL)
		return 0;

	return hdr->size;
}

// Can only append another buffer with 1 segment in it to the dest
int odp_append_fragment_to_chained_buffer(odp_buffer_t src_buf, size_t size,
					  odp_buffer_t dest_buf, int offset)
{
	odp_buffer_hdr_t *src_hdr;
	odp_buffer_hdr_t *dst_hdr;
	odp_buffer_hdr_t *segs;
	uint8_t *buf;
	uint32_t tocpy;

	src_hdr = odp_buf_to_hdr(src_buf);
	dst_hdr = odp_buf_to_hdr(dest_buf);

	// Make sure we are actually appending a fragment, no handling for
	// chained
	// buffer to chained buffer for now, or from different segment sizes.
	if (odp_is_chained_buffer(src_buf) || src_hdr->segcount > 1 ||
	    src_hdr->segsize != dst_hdr->segsize) {
		return -1;
	}

	// If the dest buffer is not a chained buffer, we need to fix up the
	// scatter list to circularly point to ourselves.
	if (!odp_is_chained_buffer(dest_buf)) {
		dst_hdr = odp_buf_to_hdr(dest_buf);
		segs = dst_hdr;
		dst_hdr->prev_segs = segs;
		segs->next_segs = dst_hdr;
		dst_hdr->num_segnodes = 1;
	}

	// Copy what we can into the destintation for now.
	tocpy = dst_hdr->size - offset;
	if ((tocpy > 0) && (odp_chained_buffer_copydata(
				dest_buf, offset, src_buf, 0, tocpy) == -1)) {
		assert(0);
		return -1;
	}

	// Need to move some bytes around if the copy is not
	// fully self contained, since this is a buffer with no scatter list,
	// this is relatively simple to do.
	if (tocpy < size) {
		buf = src_hdr->addr[0];

		// Move the remaining data to the front of the buffer
		memmove(buf, buf + tocpy, (size - tocpy));

		// Now attach into the circular list of scatter lists
		segs = dst_hdr->prev_segs;
		// If there are no slots in the scatter list, we have to
		// insert ourselves as a new node in the circular list
		if (segs->segcount == ODP_BUFFER_MAX_SEG) {
			// Add ourselves to the scatter list
			// Fix up the circular linked list
			src_hdr->next_segs = dst_hdr;
			src_hdr->prev_segs = segs;
			dst_hdr->prev_segs = src_hdr;
			segs->next_segs = src_hdr;
			src_hdr->seg_list_pos = segs->seg_list_pos++;
			src_hdr->segcount = 1;
			src_hdr->size = src_hdr->segsize;

			dst_hdr->num_segnodes++;
			dst_hdr->size += dst_hdr->segsize;
			// printf("Added new buffer to list\n");
			// else just place ourselves on the scatter list
		} else {
			segs->addr[segs->segcount++] = buf;
			// printf("Appended to segment list %d\n",
			// segs->segcount - 1);

			// if we are the first scatter to be placed here, update
			// all
			// book-keeping structures
			dst_hdr->size += dst_hdr->segsize;
			if (segs != dst_hdr) {
				segs->size += dst_hdr->segsize;
			}

			// Set buf_hdr fields correctly here
			src_hdr->addr[0] = NULL;
			src_hdr->segcount = 0;
			src_hdr->size = 0;
			src_hdr->prev_segs = NULL;
			src_hdr->next_segs = NULL;
			src_hdr->seg_list_pos = 0;
			src_hdr->num_segnodes = 0;
			_buffer_free(src_buf);
		}
		// We were able to copy the entire buffer into the existing one
	} else {
		_buffer_free(src_buf);
	}
	// printf("Appending frag %dB to pkt %dB(%dB)\n", dst_hdr->segsize,
	//    (int)(dst_hdr->size - dst_hdr->segsize), (int)dst_hdr->size);

	return 0;
}

static void set_segment_list(odp_buffer_hdr_t *seg)
{
	odp_buffer_hdr_t *seg_start = seg;
	odp_buffer_hdr_t *seg_next;
	int num_nodes = 1;

	seg_start->seg_list_pos = 0;
	seg_start->num_segnodes = num_nodes;
	if (seg_start->segcount == 0) {
		seg_start->num_segnodes = 0;
		return;
	}
	seg_next = seg->next_segs;
	assert(seg_next != NULL);

	// If a node in the scatter list has actual data in it
	while (seg_next != seg_start && seg_next->segcount > 0) {
		seg_next->seg_list_pos = num_nodes;
		seg_next = seg_next->next_segs;
		assert(seg_next != NULL);
		num_nodes++;
	}
	seg_start->num_segnodes = num_nodes;
}

// trim a chained buffer -- all segment sizes are the same.
odp_buffer_t odp_trim_chained_buffer(odp_buffer_t inbuf, int offset,
				     int *trimmed_offset)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *segs;
	odp_buffer_hdr_t *next_segs;
	// size_t src_buf_size = odp_sizeof_chained_buffer(inbuf);
	uint32_t segnode_idx = 0;
	uint32_t segsize = 0;
	int size;
	int i;

	// Is the buffer valid? Is it a chained buffer to be trimmed? Is the
	// offset valid?
	hdr = odp_buf_to_hdr(inbuf);
	if (hdr == NULL)
		return inbuf;
	if (!odp_is_chained_buffer(inbuf))
		return inbuf;
	if (offset > (int)hdr->size)
		return inbuf;

	segsize = hdr->segsize * ODP_BUFFER_MAX_SEG;
	segnode_idx = offset / segsize;
	segs = hdr;
	size = hdr->size;

	// Avoid trimming the buffer if we're at the end
	assert(hdr->num_segnodes > (int)segnode_idx);

	// printf("Trimmed buf %dB to (offset %d)", size, offset);
	// Do trim here, only on segment block boundaries.
	for (i = 0; i < (int)segnode_idx; i++) {
		next_segs = segs->next_segs;
		*trimmed_offset += segsize;
		size -= segsize;
		// Keep the list circular
		next_segs->prev_segs = segs->prev_segs;
		segs->prev_segs->next_segs = next_segs;
		segs->prev_segs = NULL;
		segs->next_segs = NULL;
		segs->seg_list_pos = 0;
		segs->num_segnodes = 0;
		_buffer_free(segs->handle.handle);
		segs = next_segs;
	}
	// printf(" %dB\n", size);
	assert(segs != NULL);
	segs->size = size;

	// If we trimmed, reset some parameters of the list
	if (*trimmed_offset) {
		set_segment_list(segs);
	}

	return segs->handle.handle;
}
