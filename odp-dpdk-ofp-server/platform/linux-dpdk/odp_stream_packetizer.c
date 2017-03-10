/* Copyright (c) 2014, ARM Limited
 * All rights reserved
 *
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 * Author: Geoffrey Blake (R&D Systems)
 */

#include <odp/api/chained_buffer.h>
#include <odp/api/debug.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/shared_memory.h>
#include <odp/api/socket_io.h>
#include <odp/api/stream_packetizer.h>

#include <odp_pool_internal.h>
#include <odp_debug_internal.h>
#include <odp_internal.h>
#include <odp_stream_packetizer_internal.h>
#include <odp_packet_internal.h>

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

/**
 * Mapping table of sockio entries to a packetizer
 */
typedef struct {
	odp_packetizer_t entries[ODP_CONFIG_SOCKIO_ENTRIES];
} pktizer_sockio_t;

/**
 * Packetizer entries
 */
typedef struct {
	odp_packetizer_entry entries[ODP_CONFIG_PACKETIZER_ENTRIES];
} pktizer_table_t;

pktizer_table_t *pktizer_tbl;
pktizer_sockio_t *sockio_to_pktizer_tbl;

static int is_free(odp_packetizer_entry *entry)
{
	return (entry->taken == 0);
}

static void init_pktizer_entry(odp_packetizer_entry *entry,
			       odp_packetizer_entry_t packetizer)
{
	entry->e = packetizer;
	entry->taken = 1;
	entry->packetizer = odp_binary_packetizer;
	entry->input_pkt_buffer = ODP_PACKET_INVALID;
	entry->inbuf_offset = 0;
}

static void lock_entry(odp_packetizer_entry *entry)
{
#ifdef PKTIZER_USE_PTHREADLOCK
	odp_pthreadlock_lock(&entry->lock);
#elif defined(PKTIZER_USE_TICKETLOCK)
	odp_ticketlock_lock(&entry->lock);
#else
	odp_spinlock_lock(&entry->lock);
#endif
}

static void unlock_entry(odp_packetizer_entry *entry)
{
#ifdef PKTIZER_USE_PTHREADLOCK
	odp_pthreadlock_unlock(&entry->lock);
#elif defined(PKTIZER_USE_TICKETLOCK)
	odp_ticketlock_unlock(&entry->lock);
#else
	odp_spinlock_unlock(&entry->lock);
#endif
}

odp_packetizer_entry *odp_packetizer_handle_to_context(odp_packetizer_t handle)
{
	uint32_t idx = _odp_typeval(handle);
	if (idx > ODP_CONFIG_PACKETIZER_ENTRIES) {
		return NULL;
	} else {
		return &pktizer_tbl->entries[idx];
	}
}

odp_packetizer_t odp_sockio_to_packetizer(odp_sockio_t sockio)
{
	uint32_t sockio_idx = _odp_typeval(sockio);
	odp_packetizer_t pktizer = sockio_to_pktizer_tbl->entries[sockio_idx];
	if (pktizer != ODP_PACKETIZER_INVALID) {
		return pktizer;
	}
	return ODP_PACKETIZER_INVALID;
}

/* Init the packetizer tables and datastructures */
int odp_packetizer_init_global(void)
{
	int i;
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_packetizer_entries", sizeof(pktizer_table_t),
			      sizeof(odp_packetizer_entry), 0);
	pktizer_tbl = odp_shm_addr(shm);

	if (pktizer_tbl == NULL)
		return -1;
	memset(pktizer_tbl, 0, sizeof(pktizer_table_t));

	shm = odp_shm_reserve("odp_pktizer_sockio_entries",
			      sizeof(pktizer_sockio_t),
			      sizeof(odp_packetizer_t), 0);
	sockio_to_pktizer_tbl = odp_shm_addr(shm);

	if (sockio_to_pktizer_tbl == NULL)
		return -1;
	memset(sockio_to_pktizer_tbl, 0, sizeof(pktizer_sockio_t));

	for (i = 0; i < ODP_CONFIG_SOCKIO_ENTRIES; i++) {
		sockio_to_pktizer_tbl->entries[i] = ODP_PACKETIZER_INVALID;
	}

	for (i = 0; i < ODP_CONFIG_PACKETIZER_ENTRIES; i++) {
		pktizer_tbl->entries[i].e.pool = ODP_POOL_INVALID;
		pktizer_tbl->entries[i].e.header_size = 0;
		pktizer_tbl->entries[i].e.size_offset = 0;
		pktizer_tbl->entries[i].e.num_bytes = 0;
		pktizer_tbl->entries[i].input_pkt_buffer = ODP_PACKET_INVALID;
		pktizer_tbl->entries[i].packetizer = NULL;
		pktizer_tbl->entries[i].taken = 0;
		pktizer_tbl->entries[i].inbuf_offset = 0;
#ifdef PKTIZER_USE_PTHREADLOCK
		odp_pthreadlock_init(&pktizer_tbl->entries[i].lock);
#elif defined(PKTIZER_USE_TICKETLOCK)
		odp_ticketlock_init(&pktizer_tbl->entries[i].lock);
#else
		odp_spinlock_init(&pktizer_tbl->entries[i].lock);
#endif
	}
	return 0;
}

int odp_packetizer_term_global(void)
{
	int i;
	for (i = 0; i < ODP_CONFIG_PACKETIZER_ENTRIES; i++) {
		odp_packetizer_destroy(_odp_cast_scalar(odp_packetizer_t, i));
	}
	return 0;
}

/* Create a simple packetizer, this is proof of concept, as a packetizer needs
 * to be a general unit as there are many L7 protocols out there. */
odp_packetizer_t odp_packetizer_create(odp_packetizer_entry_t packetizer)
{
	odp_packetizer_t id;
	odp_packetizer_entry *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PACKETIZER_ENTRIES; i++) {
		entry = &pktizer_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry(entry);
			if (is_free(entry)) {
				init_pktizer_entry(entry, packetizer);
				id = _odp_cast_scalar(odp_packetizer_t, i);
				unlock_entry(entry);
				return id; /* return without holding the lock */
			}
			unlock_entry(entry);
		}
	}

	return ODP_PACKETIZER_INVALID;
}

/* This may have strange conseqeunces for a running ODP application */
int odp_packetizer_destroy(odp_packetizer_t handle)
{
	odp_packetizer_entry *entry = &pktizer_tbl->entries[_odp_typeval(handle)];

	lock_entry(entry);
	entry->e.pool = ODP_POOL_INVALID;
	entry->e.header_size = 0;
	entry->e.size_offset = 0;
	entry->e.num_bytes = 0;
	entry->packetizer = NULL;
	unlock_entry(entry);
#ifdef PKTIZER_USE_PTHREADLOCK
	odp_pthreadlock_init(&entry->lock);
#elif defined(PKTIZER_USE_TICKETLOCK)
	odp_ticketlock_init(&entry->lock);
#else
	odp_spinlock_init(&entry->lock);
#endif

	if (entry->input_pkt_buffer != ODP_PACKET_INVALID)
		odp_packet_free(entry->input_pkt_buffer);
	entry->input_pkt_buffer = ODP_PACKET_INVALID;

	return 0;
}

/* Assign a packetizer to a sockio instance, so that any incoming buffer
 * is chopped up into the L7 packets it represents */
int odp_assign_packetizer_sockio(odp_sockio_t sockio,
				 odp_packetizer_t packetizer, odp_pool_t pool)
{
	odp_packetizer_entry *entry = &pktizer_tbl->entries[_odp_typeval(packetizer)];

	// Don't think I need to take a lock here
	sockio_to_pktizer_tbl->entries[_odp_typeval(sockio)] = packetizer;
	entry->e.pool = pool;
	return 0;
}

int odp_packetizer_bufferlen(odp_packetizer_t packetizer)
{
	// Return amount of data present in the input buffer
	odp_packetizer_entry *entry = &pktizer_tbl->entries[_odp_typeval(packetizer)];
	if (entry->input_pkt_buffer != ODP_PACKET_INVALID)
		return odp_packet_len(entry->input_pkt_buffer) -
		       entry->inbuf_offset;
	else
		return 0;
}

/* Generic function to run the packetizer
 * inputs
 * pktizer   -- handle to the pktizer to run over this input data
 * input_pkt -- input data pkt, assume for now it is a single buffer packet
 *              but ownership is passed to the packetizer for processing
 *
 * pkt_table[] -- array of packets to pass back to app or onto classifier
 * len -- length of the packet array
 *
 * return -- number of packets returned for classifier/output
 */
int odp_run_packetizer(odp_packetizer_t pktizer, odp_packet_t input_pkt,
		       odp_packet_t pkt_table[], unsigned len)
{
	odp_packetizer_entry *entry;

	entry = &pktizer_tbl->entries[_odp_typeval(pktizer)];

	return entry->packetizer(input_pkt, pkt_table, len, entry);
}

/* Binary stream protocol packetizer -- specific to memcached at the moment
 */
int odp_binary_packetizer(odp_packet_t input_pkt, odp_packet_t *pkt_table,
			  unsigned len, odp_packetizer_entry *entry)

{
	// uint8_t *buf;
	uint8_t l7hdr[ODP_CONFIG_L7_HDR_SIZE]; // Tmp buffer to hold the header
	int i;
	int pkt_offset; //, buf_offset;
	// odp_packet_t pkt_hdl;
	//odp_buffer_t buf_hdl;
	int pkts = 0;
	//odp_buffer_t trimmed_buf;
	//int trimmed_offset;
	//uint32_t pktlen;
	int ret;

	// Info about the packetizer structures and the max packet output
	// length
	uint32_t pkt_hdr_size = entry->e.header_size;
	uint32_t hdr_size_offset = entry->e.size_offset;
	uint32_t field_size = entry->e.num_bytes;
	odp_pool_t pool = entry->e.pool;
	uint32_t stream_pkt_size;
	uint32_t pkt_size;
	int copied;

	if (pkt_hdr_size > ODP_CONFIG_L7_HDR_SIZE) {
		ODP_ERR("Error: L7 packet header size of %dB larger than "
			"configured maximum!\n",
			pkt_hdr_size);
		return -1;
	}

	// If we already have an input pkt, append this one and try to trim, or
	// assign the packetizer this buffer as its initial buffer
	if (entry->input_pkt_buffer != ODP_PACKET_INVALID &&
	    input_pkt != ODP_PACKET_INVALID) {

		// Get length here before we free the buffer in the append
		// function
		//uint32_t in_pkt_len = odp_packet_len(input_pkt);
		ret = odp_packet_concat(&entry->input_pkt_buffer, input_pkt);

		if (ret < 0) {
			ODP_ERR("Failed to append pkt to input pkt\n");
			assert(0);
		}

		// Set ultimate length of the packet
		//packet_set_len(odp_packet_hdr(entry->input_pkt_buffer),
		//		   odp_packet_len(entry->input_pkt_buffer) +
		//		       in_pkt_len);
                //
		//assert(odp_packet_len(entry->input_pkt_buffer) <=
		//       odp_sizeof_chained_buffer(
	        //      _odp_packet_to_buffer(entry->input_pkt_buffer)));
		assert(odp_packet_len(entry->input_pkt_buffer) <= 1048576);
	} else if (input_pkt != ODP_PACKET_INVALID) {
		entry->input_pkt_buffer = input_pkt;
	}

	// Nothing to do, return now.
	if (entry->input_pkt_buffer == ODP_PACKET_INVALID) {
		return pkts;
	}

	// Get the total payload length
	uint32_t buf_len = odp_packet_len(entry->input_pkt_buffer);
	//buf_hdl = _odp_packet_to_buffer(entry->input_pkt_buffer);
	pkt_offset = entry->inbuf_offset;

	// Assumptions: Start of pkt buffer always contains a valid header
	//              Incoming pkt is likely a chained buffer
	for (i = 0; i < (int)len && pkt_offset < (int)buf_len; i++) {

		// If we have enough data leftover to read the header, lets
		// do so.
		if ((pkt_offset + pkt_hdr_size) <= buf_len) {
			//ret = odp_chained_buffer_copyout(
			//    buf_hdl, pkt_offset + hdr_size_offset, l7hdr,
			//    field_size);
			ret = odp_packet_copy_to_mem(entry->input_pkt_buffer,
						     pkt_offset +
						     hdr_size_offset,
						     field_size, l7hdr);
			if (odp_unlikely(ret == -1)) {
				ODP_ERR("Failed to copy field of interest out "
					"of packet\n");
				assert(0);
			}

			switch (field_size) {
			case 1:
				stream_pkt_size = (uint32_t)(l7hdr[0]);
				break;
			case 2:
				stream_pkt_size = l7hdr[0] << 8 | l7hdr[1];
				break;
			case 4:
				stream_pkt_size = l7hdr[0] << 24 |
						  l7hdr[1] << 16 |
						  l7hdr[2] << 8 | l7hdr[3];
				break;
			default:
				stream_pkt_size = 0;
				break;
			}
			pkt_size = pkt_hdr_size + stream_pkt_size;

			if (odp_unlikely(pkt_size > 1048576)) {
				ODP_ERR("Got bad data for packet size %d\n",
					stream_pkt_size);
				assert(0);
				return -1;
			}

			// If we have enough data in the packet, read the entire
			// buffer
			// into a pkt we have created.
			if (pkt_offset + pkt_size <= buf_len) {
				odp_packet_t out_pkt =
				    odp_packet_alloc(pool, pkt_size);
				// XXX: What happens if we have partially
				// consumed a buffer here?  Might have the
				// potential for duplicate outputs
				if (odp_unlikely(
					!odp_packet_is_valid(out_pkt))) {
					// Need to handle the errors here
					// gracefully.
					if (pkts)
						return pkts;
					else
						return -1;
				}
				if (odp_unlikely(
					odp_packet_len(out_pkt) < pkt_size)) {
					odp_packet_free(out_pkt);
					ODP_ERR("Allocated size of packet %d, needed %d\n", 
						odp_packet_len(out_pkt), pkt_size);
					if (pkts)
						return pkts;
					else
						return -1;
				}
				copied = odp_packet_copy_from_pkt(out_pkt, 0, 
				    entry->input_pkt_buffer,
				    pkt_offset, pkt_size);

				if (odp_unlikely(copied < 0)) {
					ODP_ERR("Got an incomplete fragment of "
						"an L7 packet\n");
					assert(0);
					if (pkts)
						return pkts;
					else
						return -1;
				}

				// Set the pkt handle here
				pkt_table[i] = out_pkt;
				pkts++;
				pkt_offset += pkt_size;
				// printf("Pktizer got pkt size %d, now at
				// offset %d\n", pkt_size, pkt_offset);
				// else we need more data from the input
				// queues/sockio
			} else {
				break;
			}
			// Need more data just for the header, need to
			// communicate this to the
			// sockio/input queue.
		} else {
			break;
		}
	}
	entry->inbuf_offset = pkt_offset;

	// If we happen to exhaust our buffer, deallocate it
	if ((unsigned)pkt_offset == buf_len) {
		odp_packet_free(entry->input_pkt_buffer);
		entry->inbuf_offset = 0;
		entry->input_pkt_buffer = ODP_PACKET_INVALID;
		//ODP_ERR("input pkt buffer used, deleting\n");
	} else {
		// trim the buffer
		// Trim the input pkt and set the bytes_free to how much space
		// is
		// left in the sliding window for the buffer
		//trimmed_offset = 0;
		//pktlen = odp_packet_len(entry->input_pkt_buffer);
		//trimmed_buf = odp_trim_chained_buffer(
		//    _odp_packet_to_buffer(entry->input_pkt_buffer), pkt_offset,
		//   &trimmed_offset);

		//if (trimmed_buf !=
		//    _odp_packet_to_buffer(entry->input_pkt_buffer)) {
		//	entry->inbuf_offset = pkt_offset - trimmed_offset;
		//	entry->input_pkt_buffer =
		//	    _odp_packet_from_buffer(trimmed_buf);
		//	packet_set_len(odp_packet_hdr(entry->input_pkt_buffer),
		//			   pktlen - trimmed_offset);

		//	assert((pktlen - trimmed_offset) <=
		//	       odp_sizeof_chained_buffer(_odp_packet_to_buffer(
		//		   entry->input_pkt_buffer)));
		//}

		// If we have finished with a segment, release it.
		if ((unsigned)pkt_offset > odp_packet_seg_len(entry->input_pkt_buffer)) {
			if (odp_packet_trunc_head(&entry->input_pkt_buffer,
						  pkt_offset, NULL, NULL) == 0){
				entry->inbuf_offset = 0;
				//ODP_ERR("truncated %d bytes\n", pkt_offset);
			} // else, the truncation failed, just keep going

		}
	}

	return pkts;
}
