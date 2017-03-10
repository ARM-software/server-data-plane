/* Copyright (c) 2017, ARM Inc
 * All rights reserved
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Implementation of asynchronous file/disk IO using ODP
 * that can be used for general server use.
 */

#include <odp_posix_extensions.h>

#include <odp/api/chained_buffer.h>
#include <odp/api/debug.h>
#include <odp/api/packet.h>
#include <odp/api/file_io.h>
#include <odp/api/queue.h>
#include <odp/api/ticketlock.h>
#include <odp/api/timer.h>

#include <odp_debug_internal.h>
#include <odp_epoll_internal.h>
#include <odp_fileio_internal.h>
#include <odp_internal.h>
#include <odp_packet_internal.h>
#include <odp_queue_internal.h>
#include <odp_schedule_if.h>

#include <assert.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static fileio_state ioqs;

// XXX: The synchronization algorithm is as follows:
// 1) Lock the ioq for dequeing
// 2) Check for any tokens available
//    a) If no, release in_service and continue
// 3) On completions, add to completion queue
// 4) Tokens are readded when the timer fires

static fileio_queue* get_fileio_by_index(uint32_t fioq_idx)
{
	if (fioq_idx > ODP_FILEIO_MAXQS) {
		return NULL;
	}
	return &(ioqs.queues[fioq_idx]);
}

// No need to return any error codes, just submit IO if we can.
static int process_fileio_q(fileio_queue *queue)
{
	odp_event_t evt;
	odp_buffer_hdr_t *evt_hdr;
	odp_buffer_t buf;
	odp_fileio_cmd_t *cmd;

	uint64_t tmp_num_evts = 0;
	uint64_t num_ios = 0;
	// Lets clear out our fd so Epoll doesn't get confused
	if (read(queue->sub_evtfd, &tmp_num_evts, sizeof(tmp_num_evts)) < 0) {
		ODP_ERR("Clearing sub_evtfd with read failed!\n");
	}
	uint32_t cur_credits = odp_atomic_load_u32(&queue->credits);
	uint32_t credits_used = 0;

	while (credits_used < cur_credits) {
		evt = odp_queue_deq(queue->ops);
		if (evt != ODP_EVENT_INVALID) {
			buf = odp_buffer_from_event(evt);
			evt_hdr = odp_buf_to_hdr(buf);
			cmd = (odp_fileio_cmd_t*)odp_buffer_addr(buf);

			uint32_t num_credits = cmd->size / BYTES_PER_TOKEN;
			if (num_credits == 0) num_credits = 1;
			if (num_credits + credits_used > cur_credits) {
				queue_prepend(queue_to_qentry(queue->ops),
					      evt_hdr);
				break;
			}

			credits_used += num_credits;

			int bytes = 0;
			int res = 0;
			while (bytes < cmd->size) {
				// Make sure to update the iovec
				// each iteration
				if (cmd->num_iovs > 0) {
					struct iovec *iov = (struct iovec*)odp_buffer_addr(cmd->iov_buf);
					struct iovec *cur_iov = iov;
					uint32_t iov_len = evt_hdr->segsize;

					cur_iov = &iov[bytes / iov_len];
					cur_iov[0].iov_len -= bytes % iov_len;
					cur_iov[0].iov_base = (char*)cur_iov[0].iov_base + bytes % iov_len;
					int num_iovs = cmd->num_iovs - (bytes / iov_len);

					if (cmd->cmd ==
					    ODP_FILEIO_READ) {
						res = preadv(cmd->fd,
							     cur_iov, num_iovs,
							     cmd->fd_offset + bytes);
					} else if ( cmd->cmd ==
						    ODP_FILEIO_WRITE) {
						res = pwritev(cmd->fd,
							     cur_iov, num_iovs,
							     cmd->fd_offset + bytes);
					} else {
						ODP_ERR("cmd->cmd = %d\n", cmd->cmd);
						ODP_ASSERT(0);
					}

					//Unmagnle iov in case we go around
					//again and haven't gotten out of this
					//iov and debugging.
					cur_iov[0].iov_len += bytes % iov_len;
					cur_iov[0].iov_base = (char*)cur_iov[0].iov_base - (bytes % iov_len);
				} else {
					char *buf = (char*)odp_buffer_addr(cmd->buffer);
					if (cmd->cmd ==
					    ODP_FILEIO_READ) {
						res = pread(cmd->fd, buf + bytes,
							    cmd->size - bytes,
							    cmd->fd_offset + bytes);
					} else if (cmd->cmd ==
						   ODP_FILEIO_WRITE) {
						res = pwrite(cmd->fd, buf + bytes,
							     cmd->size - bytes,
							     cmd->fd_offset + bytes);
					} else {
						ODP_ERR("cmd->cmd = %d\n", cmd->cmd);
						ODP_ASSERT(0);
					}
				}

				if (res < 0) {
					ODP_ERR("file read/write errored %d - %d\n", res, errno);
					ODP_ASSERT(0);
				} else if (res == 0) {
					break;
				} else {
					bytes += res;
				}
			}
			// cleanup iovs
			if (cmd->iov_buf != ODP_BUFFER_INVALID) {
				odp_buffer_free(cmd->iov_buf);
				cmd->iov_buf = ODP_BUFFER_INVALID;
			}

			cmd->status = bytes;
			_odp_buffer_event_type_set(buf,
						   ODP_EVENT_FILE_IO_COMPL);
			odp_queue_enq(queue->cmpl_q, evt);
			num_ios++;
		} else {
			// If nothing in the queue, just stop
			break;
		}
	}

	// Lets clear out our fd so Epoll doesn't get confused
	if (write(queue->cmpl_evtfd, &num_ios, sizeof(num_ios)) < 0) {
		ODP_ERR("Writing cmpl_evtfd failed!\n");
	}

	odp_atomic_sub_u32(&queue->credits, credits_used);
	odp_spinlock_unlock(&queue->in_service);

	// Put evtfd back into epoll, wait for completions before triggering
	// subs again
	sched_fn->reset_fileio(queue->index, queue->sub_evtfd,
			       (EPOLLIN | EPOLLET | EPOLLONESHOT), 0);
	return num_ios;
}

// Called from the scheduling code
int submit_fileio_ops(uint32_t fioq_idx)
{
	int num_sub = 0;
	fileio_queue *fioq = get_fileio_by_index(fioq_idx);
	// Check queue in_service -- XXX this should be a trylock and use the
	// evtfd for notifying stuff is not done.
	if (odp_spinlock_trylock(&fioq->in_service)) {
		num_sub = process_fileio_q(fioq);
	}

	return num_sub;
}

// Called from the scheduling code when something completes and the evtfd is
// notified.  This will also notify the code that input is available if there
// is stuff in the input queues.
int sweep_fileio_completions(uint32_t fioq_idx)
{
	uint64_t tmp_num_evts = 0;
	fileio_queue *fioq = get_fileio_by_index(fioq_idx);

	// Lets clear out our fd so Epoll doesn't get confused
	if (read(fioq->cmpl_evtfd, &tmp_num_evts, sizeof(tmp_num_evts)) < 0) {
		ODP_ERR("Clearing cmpl_evtfd with a read failed!\n");
	}
	// reset cmpl_fd in epoll
	sched_fn->reset_fileio(fioq->index, fioq->cmpl_evtfd,
			       (EPOLLIN | EPOLLET | EPOLLONESHOT), 1);
	// Nothing to do here now except acknowledge the epoll notification

	return (int)tmp_num_evts;
}

int add_tokens_on_tick(uint32_t fioq_idx)
{
	uint64_t tokens;
	fileio_queue *fioq = get_fileio_by_index(fioq_idx);

	// Read how many timer ticks have happened since last time we
	// serviced it.
	if (read(fioq->token_timerfd, &tokens, sizeof(tokens)) < 0) {
		ODP_ERR("Clearing token_timerfd for number of timer ticks failed!\n");
	}

	// XXX: This could be refactored to be a tad cleaner.
	uint32_t cur_tokens = odp_atomic_load_u32(&fioq->credits);
	uint32_t credits_to_return = cur_tokens + tokens * TOKENS_PER_QUEUE;

	if (credits_to_return > MAX_TOKENS_PER_QUEUE) {
		credits_to_return = MAX_TOKENS_PER_QUEUE;
	}
	credits_to_return -= cur_tokens;

	odp_atomic_add_u32(&fioq->credits, credits_to_return);

	//_odp_epoll_reset_event(fioq->token_sched_cmd, fioq->token_timerfd);
	sched_fn->reset_fileio(fioq->index, fioq->token_timerfd,
			       (EPOLLIN | EPOLLET | EPOLLONESHOT), 2);

	// Check the ops queue is not empty, make sure to force the system to
	// double check.
	if (!odp_queue_is_empty(fioq->ops)) {
		tokens = 1;
		if (write(fioq->sub_evtfd, &tokens, sizeof(uint64_t)) < 0) {
			ODP_ERR("Failed to write to sub_evtfd!\n");
		}
	}
	return (int)tokens;
}

int odp_fileio_setup(odp_fileio_params_t params)
{
	// Setup the fileio data structures with a default
	// of all zeros.
	int i;
	ioqs.num_queues = 1;
	ioqs.cq_prio = ODP_SCHED_PRIO_DEFAULT;
	char name[ODP_QUEUE_NAME_LEN];
	memset(name, 0, ODP_QUEUE_NAME_LEN);
	odp_pool_param_t iov_pool_params;
	odp_queue_param_t queue_param;
	odp_queue_t qid;

	// setup a memory pool for use by wrapper code for iovec submissions
	iov_pool_params.type = ODP_EVENT_BUFFER;
	iov_pool_params.buf.size = sizeof(struct iovec) * MAX_IOVEC;
	iov_pool_params.buf.num = 32*1024;
	iov_pool_params.buf.align = 0;
	ioqs.iov_pool = odp_pool_create("fileio_iov_pool", &iov_pool_params);
	if (ioqs.iov_pool == ODP_POOL_INVALID) {
		ODP_ERR("Error create iov_pool in odp_fileio\n");
		return -1;
	}

	// Range check how many input queues we have
	if (params.type == ODP_FILEIO_SEPERATE_QUEUES) {
		ioqs.num_queues = params.num_queues;
		if (ioqs.num_queues > ODP_FILEIO_MAXQS) {
			ioqs.num_queues = ODP_FILEIO_MAXQS;
		}
	}

	// Do range checking on the completion queue scheduling priority
	// Priorities are similar to linux, they are reverse (low number = high
	// priority etc)
	if (params.cq_prio < ODP_SCHED_PRIO_HIGHEST) {
		ioqs.cq_prio = ODP_SCHED_PRIO_HIGHEST;
	} else if (params.cq_prio > ODP_SCHED_PRIO_LOWEST) {
		ioqs.cq_prio = ODP_SCHED_PRIO_LOWEST;
	} else {
		ioqs.cq_prio = params.cq_prio;
	}

	// Wrap the libaio stuff into ODP cruft here. Append
	// to a queue if we have to, or submit directly to libaio.
	for (i = 0; i < ioqs.num_queues; i++) {
		ioqs.queues[i].sub_evtfd = eventfd(0, EFD_NONBLOCK);
		ioqs.queues[i].cmpl_evtfd = eventfd(0, EFD_NONBLOCK);
		// Setup the timer to fire every 1 ms.
		ioqs.queues[i].token_timerfd = timerfd_create(CLOCK_MONOTONIC,
							      EFD_NONBLOCK);
		struct itimerspec itr;
		itr.it_interval.tv_sec = 0;
		itr.it_interval.tv_nsec = 1000000; // 1ms
		itr.it_value.tv_sec = 0;
		itr.it_value.tv_nsec = 1000000; // 1ms
		if (timerfd_settime(ioqs.queues[i].token_timerfd, 
		    0, &itr, NULL) < 0) {
			ODP_ERR("Unable to set up token timer!\n");
			return -1;
		}

		odp_spinlock_init(&ioqs.queues[i].in_service);
		odp_atomic_init_u32(&ioqs.queues[i].credits, TOKENS_PER_QUEUE);

		// Create the completion queues and input queues
		snprintf(name, sizeof(name), "%i-fileio-opsq", i);
		name[ODP_QUEUE_NAME_LEN - 1] = '\0';
		memset(&queue_param, 0, sizeof(odp_queue_param_t));
		queue_param.type = ODP_QUEUE_TYPE_PLAIN;
		qid = odp_queue_create(name, &queue_param);
		if (qid == ODP_QUEUE_INVALID) {
			ODP_ERR("Unable to init queue for file aio\n");
			return -1;
		}
		ioqs.queues[i].ops = qid;

		// Setup the completion queue, this is scheduled for the user
		// application to pick off and do its logic after a file io.
		snprintf(name, sizeof(name), "%i-fileio-complq", i);
		name[ODP_QUEUE_NAME_LEN - 1] = '\0';
		memset(&queue_param, 0, sizeof(odp_queue_param_t));
		queue_param.type = ODP_QUEUE_TYPE_SCHED;
		queue_param.sched.prio = ioqs.cq_prio; // set the scheduling prio
		qid = odp_queue_create(name, &queue_param);
		if (qid == ODP_QUEUE_INVALID) {
			ODP_ERR("Unable to init compl queue for file aio\n");
			return -1;
		}
		ioqs.queues[i].cmpl_q = qid;
		ioqs.queues[i].index = i;

		if (sched_fn->init_fileio(i, ioqs.queues[i].sub_evtfd,
				(EPOLLET | EPOLLIN | EPOLLONESHOT), 0) < 0) {
			ODP_ERR("Unable to register fileio %d submission queue\n", i);
			return -1;
		}
		if (sched_fn->init_fileio(i, ioqs.queues[i].cmpl_evtfd,
				(EPOLLET | EPOLLIN | EPOLLONESHOT), 1) < 0) {
			ODP_ERR("Unable to register fileio %d completion queue\n", i);
			return -1;
		}
		if (sched_fn->init_fileio(i, ioqs.queues[i].token_timerfd,
				(EPOLLET | EPOLLIN | EPOLLONESHOT), 2) < 0) {
			ODP_ERR("Unable to register fileio %d token timerfd\n", i);
			return -1;
		}
		sched_fn->start_fileio(i, ioqs.queues[i].sub_evtfd, 
				(EPOLLET | EPOLLIN | EPOLLONESHOT), 0);
		sched_fn->start_fileio(i, ioqs.queues[i].cmpl_evtfd, 
				(EPOLLET | EPOLLIN | EPOLLONESHOT), 1);
		sched_fn->start_fileio(i, ioqs.queues[i].token_timerfd,
				(EPOLLET | EPOLLIN | EPOLLONESHOT), 2);
	}

	return 0;
}

// A simplish hash algorithm for using to do coarse grained sync
// This is the Knuth hash from "The Art of C Plus Plus"
static uint64_t _fileio_hash_filename(const char *str)
{
	uint64_t hash = 3074457345618258791ul;
	int len = strlen(str);
	int i;
	for (i = 0; i < len; i++) {
		hash += str[i];
		hash *= 2074457345618258799ul;
	}
	return hash;
}

// This does logically what you want, do asynchronous IO.  But should it 
// always enqueue into the queue?  Or should we have a fastpath implementation
// too?  How to do this?
int odp_fileio_post_async_op(odp_event_t fileio_cmd)
{
	// Append a the cmd to a queue and signal the eventfd
	odp_fileio_cmd_t *cmd;
	odp_buffer_hdr_t *hdr;

	// Get our command structure to start processing
	cmd = (odp_fileio_cmd_t*)odp_buffer_addr(odp_buffer_from_event(fileio_cmd));
	hdr = odp_buf_to_hdr(cmd->buffer);

	// Get the queue to work on
	uint64_t hash = _fileio_hash_filename(cmd->file_name);
	fileio_queue q = ioqs.queues[hash % ioqs.num_queues];

	cmd->hash = hash;
	cmd->iov_buf = ODP_BUFFER_INVALID;
	cmd->num_iovs = -1;

	if (hdr->segcount > 1) {
		odp_buffer_t iov_buf = odp_buffer_alloc(ioqs.iov_pool);
		if (iov_buf == ODP_BUFFER_INVALID) {
			ODP_ERR("Ran out of iov_bufs!\n");
			return -1;
		}
		struct iovec *iov;
		iov = odp_buffer_addr(iov_buf);

		int num_iovs = create_iov_list_from_buffer(cmd->buffer,
							   iov, cmd->size);

		if (num_iovs < 0) {
			odp_buffer_free(iov_buf);
			ODP_ERR("The passed in buffer is corrupt!\n");
			return -1;
		}

		cmd->iov_buf = iov_buf;
		cmd->num_iovs = num_iovs;
	}
	odp_queue_enq(q.ops, fileio_cmd);

	// Place the completed cmd onto the proper queue and signal the evtfd
	// for the scheduling loop to pick up.
	uint64_t tmp = 1;
	if (write(q.sub_evtfd, &tmp, sizeof(uint64_t)) < 0) {
		ODP_ERR("Writing to sub_evtfd has failed!?\n");
	}

	return 0;
}

// Do synchronous IO here, it does not do any hashing or checking with any
// in-flight async IO.  This may be a feature in the future.
int odp_fileio_sync_op(odp_fileio_cmd_t *cmd)
{
	// Append a the cmd to a queue and signal the eventfd
	odp_buffer_hdr_t *hdr;
	void *buffer;
	int ret = 0;

	// Get our command structure to start processing
	hdr = odp_buf_to_hdr(cmd->buffer);

	// Do normal IO here, just blocking pread/pwrite
	if (cmd->cmd == ODP_FILEIO_READ) {
		if (hdr->segcount == 1) {
			buffer = odp_buffer_addr(cmd->buffer);
			// Should be a blocking read here
			ret = read(cmd->fd, buffer, cmd->size);
		} else {
			// XXX: Put in support here, but do it later
			ODP_ERR("No support for building an iovec yet!\n");
		}
	} else if (cmd->cmd == ODP_FILEIO_WRITE) {
		if (hdr->segcount == 1) {
			buffer = odp_buffer_addr(cmd->buffer);
			ret = write(cmd->fd, buffer, cmd->size);
		}else {
			// XX: Put it support here but do it later
			ODP_ERR("No support for building an iovec yet!\n");
		}
	} else {
		ODP_ERR("Unknown command passed!\n");
		return -1;
	}

	return ret;
}

void odp_fileio_cmpl_free(odp_buffer_t file_cmpl)
{
	odp_fileio_cmd_t *cmd;
	_odp_buffer_event_type_set(file_cmpl, ODP_EVENT_BUFFER);
	cmd = odp_buffer_addr(file_cmpl);
	// zero out the completion in case it comes back from the dead.
	memset(cmd, 0, sizeof(odp_fileio_cmd_t));
	cmd->buffer = ODP_BUFFER_INVALID;
	cmd->iov_buf = ODP_BUFFER_INVALID;
	cmd->num_iovs = -1;
	odp_buffer_free(file_cmpl);
}

// Scans through the buffer headers to build the iovec array.
int create_iov_list_from_buffer(odp_buffer_t buf, struct iovec *iov, size_t buf_size)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *segs;
	int i = 0;
	int segment_size;

	hdr = odp_buf_to_hdr(buf);
	segs = hdr;

	segment_size = hdr->segsize;

	if ((buf_size / segment_size) > MAX_IOVEC) {
		ODP_ERR("Buffer is too big to construct an iovec!\n");
		return -1;
	}

	int to_map = buf_size;
	memset(iov, 0, sizeof(struct iovec)*MAX_IOVEC);	

	// Loop around the buffer segments
	while (to_map > 0) {
		iov[i].iov_base = segs->addr[(i % ODP_BUFFER_MAX_SEG)];
		iov[i].iov_len = (to_map < segment_size) ? to_map : segment_size;

		to_map -= (to_map < segment_size) ? to_map : segment_size;
		if ((++i % ODP_BUFFER_MAX_SEG) == 0) {
			segs = segs->next_segs;
		}
	}
	ODP_ASSERT(to_map == 0 );
	ODP_ASSERT(i == (int)(buf_size / segment_size) || 
		   i - 1 == (int)(buf_size / segment_size));
	return i;
}
