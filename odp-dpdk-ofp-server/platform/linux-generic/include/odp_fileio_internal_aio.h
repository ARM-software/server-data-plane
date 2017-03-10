/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_FILEIO_INTERNAL_H_
#define ODP_FILEIO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/* XXX: This is the header for the version that uses kernel
 *      aio for async IO.  This version seems fundamentally
 *      broken on the aio layer as I have seen issues with
 *      duplicate completions and seemingly corrupt completions.
 */

#include <odp/api/atomic.h>
#include <odp/api/event.h>
#include <odp/api/queue.h>
#include <odp/api/file_io.h>
#include <odp/api/ticketlock.h>

#include <libaio.h>

// Tokens represent 4kB of data.
#define BYTES_PER_TOKEN 4096
#define TOKENS_PER_QUEUE 256 // allow a queue to submit up to 256 ops at once or
			     // up to 1MB of outstanding IO for now...

#define ODP_FILEIO_MAXQS 16
#define ODP_AIO_MAX 256
#define ODP_FILEIO_SCOREBOARD_MAX 64
#define MAX_IOVEC 256 // allow for an iovec of a maximum of 256 entries

// Will use a home-brew variant of the Token bucket algorithm
// to meter out bandwidth. Will only allow 1 thread to service a queue
// at a time (sending out io's).  Multiple threads can append to and deque
// from the completion queues though.
typedef struct {
	// These are funnels using a hash algorithm on the file
	// name to pick a funnel.  The mutual exclusion is coarse
	// grained in this respect, but maybe it will work.
	odp_queue_t ops;
	// This bitmask allows us to track in flight requests, but only
	// one request per hash can be submitted at a time.  This reduces the
	// need for lots of bucket locks as we use coarser protection with the
	// queues.
	//uint64_t in_flight_scoreboard[ODP_AIO_MAX / (sizeof(uint64_t) * 8)]; 
	struct iocb* in_flight_scoreboard[ODP_FILEIO_SCOREBOARD_MAX];

	odp_queue_t cmpl_q;
	odp_atomic_u32_t credits;

	io_context_t aio_ctx;
	int cmpl_evtfd;
	int sub_evtfd;

	odp_event_t cmpl_sched_cmd;
	odp_event_t sub_sched_cmd;
	//odp_atomic_u32_t in_service;
	odp_ticketlock_t in_service;
} fileio_queue;

// start simple first, then can add LRU lists, most full tracking etc
typedef struct {
	fileio_queue queues[ODP_FILEIO_MAXQS];

	int num_queues;
	int cq_prio;
	odp_pool_t iov_pool; //allocator pool meant to allocate iovecs for long
			     //accesses, not truly general purpose, but should
			     //be tuned for workload.
	odp_pool_t iocb_pool; // Allocator pool meant to allocate iocb
			      // buffers for the libaio calls
} fileio_state;

void odp_fileio_cmpl_free(odp_buffer_t file_cmpl);
int submit_fileio_ops(fileio_queue *fioq);
int sweep_fileio_completions(fileio_queue *fioq);
int create_iov_list_from_buffer(odp_buffer_t buf, struct iovec *iov,
				size_t buf_size);
// update an iocb to be resubmitted into the kernel
void reenqueue_ioop(odp_buffer_t fileio_cmd, odp_fileio_cmd_t *cmd, fileio_queue *fioq);

#ifdef __cplusplus
}
#endif

#endif
