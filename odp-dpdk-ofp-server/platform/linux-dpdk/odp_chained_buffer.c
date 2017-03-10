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
 * while DPDK supports it, we need a standard interface for all of
 * ODP-DPDK and not just the packet interface.
 */

#include <odp/api/chained_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>

#include <odp_packet_dpdk.h>

#include <assert.h>
#include <string.h>

#define odp_min(a, b) (a <= b) ? a : b

odp_buffer_t odp_chained_buffer_alloc(odp_pool_t pool_hdl, size_t total_size)
{
	odp_buffer_t buf;
	odp_buffer_hdr_t *buf_hdr;
	struct rte_mbuf *mbuf;
	pool_entry_t *pool_entry =
		get_pool_entry(pool_handle_to_index(pool_hdl));

	int num_segs = total_size / pool_entry->s.params.buf.size;
	if (total_size % pool_entry->s.params.buf.size)
		num_segs++;

	mbuf = rte_pktmbuf_alloc(pool_entry->s.rte_mempool);
	if (mbuf == NULL) {
		rte_errno = ENOMEM;
		return ODP_BUFFER_INVALID;
	}

	buf_hdr = (odp_buffer_hdr_t *)mbuf;
	buf_hdr->totsize = num_segs * pool_entry->s.params.buf.size;
	buf_hdr->size = total_size;

	int i;
	struct rte_mbuf *curseg = mbuf;
	struct rte_mbuf *nextseg = NULL;
	for (i = 1; i < num_segs; i++) {
		nextseg = rte_pktmbuf_alloc(pool_entry->s.rte_mempool);
		if (nextseg == NULL) {
			// DPDK knows how to free buffer chains
			rte_pktmbuf_free(mbuf);
			return ODP_BUFFER_INVALID;
		}

		curseg->next = nextseg;
		curseg = nextseg;
		curseg->data_off = 0;
	}

	buf = (odp_buffer_t)mbuf;

	return buf;
}

void odp_chained_buffer_free(odp_buffer_t buf)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf*)buf;
	if (buf != ODP_BUFFER_INVALID) {
		rte_pktmbuf_free(mbuf);
	}
}

int odp_chained_buffer_copyin(odp_buffer_t cbuf, int offset,
			      const uint8_t *ibuf, size_t size)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(cbuf);
	uint8_t *mapaddr = NULL;
	uint32_t seglen = 0;
	uint32_t cpylen;
	size_t buf_size;

	// Is the buffer valid?
	if (hdr == NULL)
		return -1;

	buf_size = odp_sizeof_chained_buffer(cbuf);
	// Check if we can copy over all the data, if not, return error
	if (offset + size > buf_size)
		return -1;

	while (size > 0) {
		mapaddr = buffer_map(hdr, offset, &seglen, 0);
		cpylen = size > seglen ? seglen : size;
		memcpy(mapaddr, ibuf, cpylen);
		size -= cpylen;
		offset += cpylen;
		ibuf += cpylen;
	}

	return 0;
}

int odp_chained_buffer_copyout(odp_buffer_t cbuf, int offset, uint8_t *obuf,
			       size_t size)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(cbuf);
	uint8_t *mapaddr = NULL;
	uint32_t seglen = 0;
	uint32_t cpylen;

	size_t buf_size;

	// Is the buffer valid?
	if (hdr == NULL)
		return -1;

	buf_size = odp_sizeof_chained_buffer(cbuf);
	// Check if we can copy over all the data, if not, return error
	if (offset + size > buf_size)
		return -1;

	while (size > 0) {
		mapaddr = buffer_map(hdr, offset, &seglen, 0);
		cpylen = size > seglen ? seglen : size;
		memcpy(obuf, mapaddr, cpylen);
		size -= cpylen;
		offset += cpylen;
		obuf += cpylen;
	}

	return 0;
}

int odp_chained_buffer_copydata(odp_buffer_t cbuf_dest, int offset_dest,
				odp_buffer_t cbuf_src, int offset_src,
				size_t size)
{
	odp_buffer_hdr_t *dsthdr = odp_buf_to_hdr(cbuf_dest);
	odp_buffer_hdr_t *srchdr = odp_buf_to_hdr(cbuf_src);
	uint8_t *dstmapaddr = NULL;
	uint8_t *srcmapaddr = NULL;
	uint32_t dstseglen = 0;
	uint32_t srcseglen = 0;
	uint32_t cpylen;
	uint32_t minseg;

	size_t dst_size = odp_sizeof_chained_buffer(cbuf_dest);
	size_t src_size = odp_sizeof_chained_buffer(cbuf_src);

	if (dsthdr == NULL || srchdr == NULL) {
		assert(0);
		return -1;
	}

	// no overlap allowed
	assert(dsthdr != srchdr);

	// Check if we can copy over all the data, if not, return error
	if (offset_dest + size > dst_size) {
		ODP_ERR("offset: %d size: %d buf_size: %d\n", offset_dest, size, dst_size);
		assert(0);
		return -1;
	}
	if (offset_src + size > src_size) {
		assert(0);
		return -1;
	}

	// Loop through linked list of scatter/gather lists
	while (size) {
		dstmapaddr = (uint8_t *)buffer_map(dsthdr, offset_dest,
						   &dstseglen, 0);
		srcmapaddr = (uint8_t *)buffer_map(srchdr, offset_src,
						   &srcseglen, 0);
		minseg = dstseglen > srcseglen ? srcseglen : dstseglen;
		cpylen = size > minseg ? minseg : size;

		memcpy(dstmapaddr, srcmapaddr, cpylen);

		offset_src += cpylen;
		offset_dest += cpylen;
		size -= cpylen;
	}

	return 0;
}

int odp_is_chained_buffer(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	struct rte_mbuf *mb;
	if (hdr == NULL)
		return 0;

	mb = &(hdr->mb);
	// Num segnodes only gets populated if
	// allocated by the chained buffer code
	if (mb->next != NULL) {
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

	return hdr->totsize;
}

// Can only append another buffer with 1 segment in it to the dest
// XXX: Even though DPDK uses a simply linked list, keep the restriction
//      of only 1 segment to avoid having to write code for shuffling data.
int odp_append_fragment_to_chained_buffer(odp_buffer_t src_buf, size_t size,
					  odp_buffer_t dest_buf, int offset)
{
	odp_buffer_hdr_t *src_hdr;
	odp_buffer_hdr_t *dst_hdr;
	uint32_t seglen;
	uint8_t *buf;
	uint32_t tocpy;

	src_hdr = odp_buf_to_hdr(src_buf);
	dst_hdr = odp_buf_to_hdr(dest_buf);

	// Make sure we are actually appending a fragment
	struct rte_mbuf *mb = &(src_hdr->mb);
	if (mb->next != NULL) {
		return -1;
	}

	// Copy what we can into the destintation for now.
	tocpy = odp_sizeof_chained_buffer(dest_buf) - offset;
	if ((tocpy > 0) &&
	    (odp_chained_buffer_copydata(dest_buf, offset, src_buf, 0, tocpy) == -1)) {
		assert(0);
		return -1;
	}

	// Need to move some bytes around if the copy is not
	// fully self contained, since this is a buffer with no scatter list,
	// this is relatively simple to do.
	if (tocpy < size) {
		buf = buffer_map(src_hdr, 0, &seglen, 0);

		// Move the remaining data to the front of the buffer
		memmove(buf, buf + tocpy, (size - tocpy));

		// Find the end of rte_mbuf chain and just place the src buf
		// there.  No need to clean up I think.
		struct rte_mbuf *mb, *srcmb, *nextmb;
		mb = &(dst_hdr->mb);
		srcmb = &(src_hdr->mb);
		nextmb = mb->next;
		while (nextmb) {
			mb = nextmb;
			nextmb = mb->next;
		}

		mb->next = srcmb;
		srcmb->next = NULL;

		dst_hdr->totsize += src_hdr->totsize;
		// We were able to copy the entire buffer into the existing one
	} else {
		odp_buffer_free(src_buf);
	}
	// printf("Appending frag %dB to pkt %dB(%dB)\n", dst_hdr->segsize,
	//    (int)(dst_hdr->size - dst_hdr->segsize), (int)dst_hdr->size);

	return 0;
}

// trim a chained buffer -- all segment sizes are the same.
odp_buffer_t odp_trim_chained_buffer(odp_buffer_t inbuf, int offset,
				     int *trimmed_offset)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *new_hdr;
	struct rte_mbuf *mb, *curmb, *nextmb;
	int new_size = odp_sizeof_chained_buffer(inbuf);

	// Is the buffer valid? Is it a chained buffer to be trimmed? Is the
	// offset valid?
	hdr = odp_buf_to_hdr(inbuf);
	if (hdr == NULL)
		return inbuf;
	if (!odp_is_chained_buffer(inbuf))
		return inbuf;
	if (offset > (int)hdr->size)
		return inbuf;

	mb = &(hdr->mb);
	curmb = mb;
	nextmb = mb->next;

	// Walk the list two nodes at a time, looking for when offset
	// lies inside the second node, then cut the chain between the
	// current and next pointers.
	// If the offset is inside the head pkt, return
	if (offset < curmb->data_len)
		return inbuf;

	while (offset) {
		if (offset < (curmb->data_len + nextmb->data_len) &&
		    offset >= (curmb->data_len)) {
			*trimmed_offset = nextmb->data_len - (offset - curmb->data_len);
			new_hdr = (odp_buffer_hdr_t *) nextmb;
			new_hdr->totsize = new_size - curmb->data_len;
			new_hdr->size = new_size - curmb->data_len;
			curmb->next = NULL; // cut the chain to free the trimmed portion
			offset = 0;
		} else {
			offset -= curmb->data_len;
			new_size -= curmb->data_len;

			curmb = nextmb;
			nextmb = curmb->next;
		}
	}

	rte_pktmbuf_free(mb);

	return (odp_buffer_t)curmb;
}
