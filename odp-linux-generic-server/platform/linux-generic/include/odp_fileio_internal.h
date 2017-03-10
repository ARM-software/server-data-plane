/* Copyright (c) 2017, ARM Inc
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_FILEIO_INTERNAL_H_
#define ODP_FILEIO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/uio.h>

#include <odp/api/atomic.h>
#include <odp/api/event.h>
#include <odp/api/queue.h>
#include <odp/api/file_io.h>
#include <odp/api/spinlock.h>
#include <odp_config_internal.h>

/* Implement a user space async IO framework using
 * ODP.  A different version using libaio is also
 * present in this project, but seems to not be working
 * for unknown reasons.  Current theory is kernel aio
 * sometimes hits errors.
 */

// epoll flags for fileio EPOLLET | EPOLLIN | EPOLLONESHOT

// Tokens represent 4kB of data.
#define BYTES_PER_TOKEN 4096
#define TOKENS_PER_QUEUE 1024 // allow a queue to submit up to 256 ops at once or
			     // up to 4MB of outstanding IO for now...
#define MAX_TOKENS_PER_QUEUE 2048

#define ODP_FILEIO_MAXQS ODP_CONFIG_FILEIO_QS
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
	odp_queue_t cmpl_q;

	odp_atomic_u32_t credits;

	int cmpl_evtfd;
	int sub_evtfd;
	int token_timerfd;

	odp_event_t cmpl_sched_cmd;
	odp_event_t sub_sched_cmd;
	odp_event_t token_sched_cmd;

	odp_spinlock_t in_service;
	int index;
} fileio_queue;

// start simple first, then can add LRU lists, most full tracking etc
typedef struct {
	fileio_queue queues[ODP_FILEIO_MAXQS];

	int num_queues;
	int cq_prio;
	odp_pool_t iov_pool; //allocator pool meant to allocate iovecs for long
			     //accesses, not truly general purpose, but should
			     //be tuned for workload.
} fileio_state;

void odp_fileio_cmpl_free(odp_buffer_t file_cmpl);
int submit_fileio_ops(uint32_t fioq_idx);
int sweep_fileio_completions(uint32_t fioq_idx);
int add_tokens_on_tick(uint32_t fioq_idx);

int create_iov_list_from_buffer(odp_buffer_t buf, struct iovec *iov, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif
