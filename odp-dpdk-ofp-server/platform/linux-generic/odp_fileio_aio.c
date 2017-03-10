/* Copyright (c) 2017, ARM Limited
 * All rights reserved
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Implementation of asynchronous file/disk IO for ODP
 * that can be used for general server use.
 * XXX: This implementation is somehow broken and hitting many
 *      many issues with linux kernel aio. Even with conservative
 *      synchronization I am getting what seems to be duplicate IO
 *      completions as I continually hit issues where a fileio_cmd
 *      buffer is already partially cleaned up, but I try doing it
 *      again. Have tried numerous workarounds such as hacking the
 *      kernel, and being extremely careful with my book-keeping but the
 *      bug is elusive.
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
#include <odp_schedule_internal.h>

#include <assert.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static fileio_state ioqs;

// XXX: The synchronization algorithm is as follows:
// 1) Lock the ioq for dequeing by setting the "in_service" flag
// 2) Check for any tokens available
//    a) If no, release in_service and continue
// 3) For each entry in the ops queue, try to schedule it by checking
//    the inflight scoreboard
// 4) If the scoreboard has no bit set, submit the IO
//    a) If the bit is set, place the command to the side and try to schedule
//    another
// 5) Prepend any ops to the ops queue that are 'blocked'
// 6) On completions, add tokens back into the bucket

#define SHELF_SIZE 64

// No need to return any error codes, just submit IO if we can.
static int process_fileio_q(fileio_queue *queue)
{
	odp_buffer_hdr_t *evt_shelf[SHELF_SIZE];
	int shelf_idx = 0;
	odp_event_t evt;
	odp_buffer_hdr_t *evt_hdr;
	odp_buffer_t buf;
	odp_fileio_cmd_t *cmd;
	struct iocb *iocb_cmd;
	struct iocb *ios[ODP_AIO_MAX];
	int num_aios = 0;

	uint64_t tmp_num_evts = 0;
	// Lets clear out our fd so Epoll doesn't get confused
	if (read(queue->sub_evtfd, &tmp_num_evts, sizeof(tmp_num_evts)) < 0) {
		ODP_ERR("Clearing sub_evtfd with read failed!\n");
	}
	uint32_t cur_credits = odp_atomic_load_u32(&queue->credits);
	if (cur_credits > 0) {
		// XXX: Probably should not be mixing internal and external ops,
		// but don't care right now.

		while (/*cur_credits > 0 &&*/
		       shelf_idx < SHELF_SIZE &&
		       num_aios < ODP_AIO_MAX) {
			evt = odp_queue_deq(queue->ops);
			if (evt != ODP_EVENT_INVALID) {
				buf = odp_buffer_from_event(evt);
				evt_hdr = odp_buf_to_hdr(buf);
				cmd = (odp_fileio_cmd_t*)odp_buffer_addr(buf);
				// XXX: Only allow 64 outstanding requests for now ... trying to debug AIO
				// Check bitmask if we can go, otherwise, put on shelf
				uint64_t index = (cmd->hash >> ODP_FILEIO_MAXQS)
					         % ODP_FILEIO_SCOREBOARD_MAX;

				if (queue->in_flight_scoreboard[index] != NULL) {
					// Store the event on the shelf and
					// continue
					evt_shelf[shelf_idx] = evt_hdr;
					shelf_idx ++;
				} else {

					uint32_t num_credits = cmd->size / BYTES_PER_TOKEN;
					if (num_credits > cur_credits) {
						cur_credits = 0; // allow a little slop here
					} else {
						cur_credits -= num_credits;
					}
					// Set the scoreboard
					iocb_cmd = (struct iocb*)odp_buffer_addr(cmd->iocb);
					queue->in_flight_scoreboard[index] = iocb_cmd;

					//ODP_ERR("%d - %llx\n", queue->sub_evtfd, queue->in_flight_scoreboard[0]);
					ios[num_aios] = iocb_cmd;
					num_aios++;
				}
			} else {
				// If nothing in the queue, just stop
				break;
			}
		}
	}

	// Place any events that on the shelf back into the queue
	if (shelf_idx > 0) {
		queue_prepend_multi(queue_to_qentry(queue->ops), evt_shelf,
				    shelf_idx);
	}
	if (num_aios > 0) {
		// Place events from ios into io_submit;
		int res = io_submit(queue->aio_ctx, num_aios, ios);
		if (res < num_aios) {
			ODP_ERR("io_submit failed - %d\n", res);
		}
	}
	odp_atomic_store_rel_u32(&queue->credits, cur_credits);
	// Release in_service here before arming the fd.
	//odp_atomic_store_rel_u32(&queue->in_service, 0);

	// Put evtfd back into epoll, wait for completions before triggering
	// subs again
	_odp_epoll_reset_event(queue->sub_sched_cmd, queue->sub_evtfd);
	return num_aios;
}

// Called from the scheduling code
int submit_fileio_ops(fileio_queue *fioq)
{
	int num_sub = 0;
	// Check queue in_service
	//uint32_t old_val = odp_atomic_load_u32(&fioq->in_service);
	odp_ticketlock_lock(&fioq->in_service);
	{
		num_sub = process_fileio_q(fioq);
	}
	odp_ticketlock_unlock(&fioq->in_service);

	return num_sub;
}

// Called from the scheduling code when something completes and the evtfd is
// notified.  This will also notify the code that input is available if there
// is stuff in the input queues.
int sweep_fileio_completions(fileio_queue *fioq)
{
	struct io_event io_evt;
	struct iocb *iocb;
	odp_fileio_cmd_t *cmd;
	odp_buffer_t fileio_cmd;
	odp_buffer_t iocb_buf;
	struct timespec aio_tmo;
	aio_tmo.tv_sec = 0;
	aio_tmo.tv_nsec = 0;
	io_context_t aio_ctx = fioq->aio_ctx;
	uint32_t credits_to_return = 0;
	int num_evts = 0;

	// Keep getting events one at a time until we run out
	uint64_t tmp_num_evts = 0;

	odp_ticketlock_lock(&fioq->in_service);
	// Lets clear out our fd so Epoll doesn't get confused
	if (read(fioq->cmpl_evtfd, &tmp_num_evts, sizeof(tmp_num_evts)) < 0) {
		ODP_ERR("Clearing cmpl_evtfd with a read failed!\n");
	}
	while (io_getevents(aio_ctx, 1, 1, &io_evt, &aio_tmo) > 0) {
		iocb = io_evt.obj;
		fileio_cmd = io_evt.data;

		assert((int)iocb->u.c.resfd == fioq->cmpl_evtfd);
		assert(fileio_cmd != ODP_BUFFER_INVALID);

		cmd = (odp_fileio_cmd_t*)odp_buffer_addr(fileio_cmd);
		ODP_ASSERT(cmd->cmd != 0);

		iocb_buf = cmd->iocb;
		struct iocb *iocb_cmd = (struct iocb*)odp_buffer_addr(iocb_buf);
		cmd->status += io_evt.res; // Set status to number of bytes
		                          // written/read.  Let application
					  // deal with descrepancies.

		uint64_t index = (cmd->hash >> ODP_FILEIO_MAXQS) %
				  ODP_FILEIO_SCOREBOARD_MAX;

		if (fioq->in_flight_scoreboard[index] == iocb_cmd
		    && cmd->status == cmd->size) {
			_odp_buffer_event_type_set(fileio_cmd, ODP_EVENT_FILE_IO_COMPL);
			odp_queue_enq(fioq->cmpl_q, odp_buffer_to_event(fileio_cmd));
			cmd->iocb = ODP_BUFFER_INVALID;
			// Free the iocb buffer here because phantom IO should be invalid...
			// Hoping renotifications are a benign bug ... 
			// confident the mutual exclusion on my end is working
			iocb = (struct iocb*)odp_buffer_addr(iocb_buf);
			memset(iocb, 0, sizeof(struct iocb)); // zero out the iocb
			                                      // in case it rises from the dead.
			odp_buffer_free(iocb_buf);

			if (cmd->iov_buf != ODP_BUFFER_INVALID) {
				odp_buffer_free(cmd->iov_buf);
				cmd->iov_buf = ODP_BUFFER_INVALID;
			}
			num_evts++;
			fioq->in_flight_scoreboard[index] = NULL;
		} else if (fioq->in_flight_scoreboard[index] == iocb_cmd) {
			// Need to send the command back through the libaio
			// framework to try and complete it. Atomicity still
			// guaranteed because we have not freed our entry in the
			// scoreboard.
			reenqueue_ioop(fileio_cmd, cmd, fioq);
		} else {
			ODP_ERR("Phantom fileio detected!\n");
		}
		credits_to_return += cmd->size / BYTES_PER_TOKEN;
	}

	// reset cmpl_fd in epoll
	_odp_epoll_reset_event(fioq->cmpl_sched_cmd, fioq->cmpl_evtfd);
	uint32_t cur_tokens = odp_atomic_load_u32(&fioq->credits);
	if (credits_to_return + cur_tokens > TOKENS_PER_QUEUE) {
		credits_to_return = TOKENS_PER_QUEUE - cur_tokens;
	}
	odp_atomic_add_u32(&fioq->credits, credits_to_return);

	// Check if ops queue is not empty, make sure the system double-checks
	if (!odp_queue_is_empty(fioq->ops)) {
		uint64_t tmp = 1;
		if (write(fioq->sub_evtfd, &tmp, sizeof(uint64_t)) < 0) {
			ODP_ERR("Failed to write to sub_evtfd!\n");
		}
	}
	odp_ticketlock_unlock(&fioq->in_service);
	return num_evts;
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
	odp_pool_param_t iocb_pool_params;
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

	// setup a memory pool for use by wrapper code for iocb structures
	iocb_pool_params.type = ODP_EVENT_BUFFER;
	iocb_pool_params.buf.size = sizeof(struct iocb);
	iocb_pool_params.buf.num = 32*1024;
	iocb_pool_params.buf.align = 0;
	ioqs.iocb_pool = odp_pool_create("fileio_iocb_pool", &iocb_pool_params);
	if (ioqs.iocb_pool == ODP_POOL_INVALID) {
		ODP_ERR("Error create iocb_pool in odp_fileio\n");
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
		memset(&ioqs.queues[i].aio_ctx, 0,
		       sizeof(ioqs.queues[i].aio_ctx));
		memset(ioqs.queues[i].in_flight_scoreboard, 0, 
                       sizeof(ioqs.queues[i].in_flight_scoreboard));
		ioqs.queues[i].sub_evtfd = eventfd(0, EFD_NONBLOCK);
		ioqs.queues[i].cmpl_evtfd = eventfd(0, EFD_NONBLOCK);
		if (io_setup(ODP_AIO_MAX, &ioqs.queues[i].aio_ctx) < 0) {
			ODP_ERR("Unable to init libaio queue %d!\n", i);
			return -1;
		}
		//odp_atomic_init_u32(&ioqs.queues[i].in_service, 0);
		odp_ticketlock_init(&ioqs.queues[i].in_service);
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

		if (schedule_fileioq_init(&ioqs.queues[i]) < 0) {
			ODP_ERR("Unable to create schedule command for ioqs\n");
			return -1;
		}
		// Let the descriptors start scheduling in the odp_schedule code
		_odp_epoll_set_event(ioqs.queues[i].sub_sched_cmd,
				     ioqs.queues[i].sub_evtfd);
		_odp_epoll_set_event(ioqs.queues[i].cmpl_sched_cmd,
				     ioqs.queues[i].cmpl_evtfd);
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
	odp_buffer_t iocb_buf;
	struct iocb *iocb_cmd;
	odp_buffer_hdr_t *hdr;
	void *buffer;

	// Get our command structure to start processing
	cmd = (odp_fileio_cmd_t*)odp_buffer_addr(odp_buffer_from_event(fileio_cmd));
	hdr = odp_buf_to_hdr(cmd->buffer);

	// Get the queue to work on
	uint64_t hash = _fileio_hash_filename(cmd->file_name);
	fileio_queue q = ioqs.queues[hash % ioqs.num_queues];

	iocb_buf = odp_buffer_alloc(ioqs.iocb_pool);
	if (iocb_buf == ODP_BUFFER_INVALID) {
		ODP_ERR("Too much concurrent IO! Ran out of iocb buffers.\n");
	}
        iocb_cmd = (struct iocb*)odp_buffer_addr(iocb_buf);
	cmd->hash = hash;
	cmd->iov_buf = ODP_BUFFER_INVALID;

	if (cmd->cmd == ODP_FILEIO_READ) {
		if (hdr->segcount == 1) {
			buffer = odp_buffer_addr(cmd->buffer);
			io_prep_pread(iocb_cmd, cmd->fd, buffer, cmd->size,
				      cmd->fd_offset);
			io_set_eventfd(iocb_cmd, q.cmpl_evtfd);
			iocb_cmd->data = (void*)fileio_cmd;
			cmd->iocb = iocb_buf;
			odp_queue_enq(q.ops, fileio_cmd);
		} else {
			odp_buffer_t iov_buf = odp_buffer_alloc(ioqs.iov_pool);
			if (iov_buf == ODP_BUFFER_INVALID) {
				ODP_ERR("Ran out of iov_bufs!\n");
				return -1;
			}
			struct iovec *iov;
			iov = odp_buffer_addr(iov_buf);

			int num_iovs = create_iov_list_from_buffer(cmd->buffer,
								   iov, cmd->size, 0);

			if (num_iovs < 0) {
				odp_buffer_free(iov_buf);
				ODP_ERR("The passed in buffer is corrupt!\n");
				return -1;
			}
			io_prep_preadv(iocb_cmd, cmd->fd, iov, num_iovs,
				       cmd->fd_offset);
			io_set_eventfd(iocb_cmd, q.cmpl_evtfd);
			iocb_cmd->data = (void*)fileio_cmd;
			cmd->iocb = iocb_buf;
			cmd->iov_buf = iov_buf;
			odp_queue_enq(q.ops, fileio_cmd);
			//ODP_ERR("No support for building an iovec yet!\n");
		}
	} else if (cmd->cmd == ODP_FILEIO_WRITE) {
		if (hdr->segcount == 1) {
			buffer = odp_buffer_addr(cmd->buffer);
			io_prep_pwrite(iocb_cmd, cmd->fd, buffer, cmd->size,
				       cmd->fd_offset);
			io_set_eventfd(iocb_cmd, q.cmpl_evtfd);
			iocb_cmd->data = (void*)fileio_cmd;
			cmd->iocb = iocb_buf;
			odp_queue_enq(q.ops, fileio_cmd);
		} else {
			odp_buffer_t iov_buf = odp_buffer_alloc(ioqs.iov_pool);
			if (iov_buf == ODP_BUFFER_INVALID) {
				ODP_ERR("Ran out of iov_bufs!\n");
				return -1;
			}
			struct iovec *iov;
			iov = odp_buffer_addr(iov_buf);

			int num_iovs = create_iov_list_from_buffer(cmd->buffer,
								   iov, cmd->size, 0);

			if (num_iovs < 0) {
				odp_buffer_free(iov_buf);
				ODP_ERR("The passed in buffer is corrupt!\n");
				return -1;
			}
			io_prep_pwritev(iocb_cmd, cmd->fd, iov, num_iovs,
				       cmd->fd_offset);
			io_set_eventfd(iocb_cmd, q.cmpl_evtfd);
			iocb_cmd->data = (void*)fileio_cmd;
			cmd->iocb = iocb_buf;
			cmd->iov_buf = iov_buf;
			odp_queue_enq(q.ops, fileio_cmd);
		}
	} else {
		ODP_ERR("Unknown command passed!\n");
		return -1;
	}

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
	cmd->iocb = ODP_BUFFER_INVALID;
	cmd->iov_buf = ODP_BUFFER_INVALID;
	odp_buffer_free(file_cmpl);
}

// Scans through the buffer headers to build the iovec array.
int create_iov_list_from_buffer(odp_buffer_t buf, struct iovec *iov, 
				size_t buf_size, size_t buf_offset)
{
	odp_buffer_hdr_t *hdr;
	odp_buffer_hdr_t *segs;
	int i = 0;
	int j = 0;
	int segment_size;

	hdr = odp_buf_to_hdr(buf);
	segs = hdr;

	segment_size = hdr->segsize;

	if ((buf_size / segment_size) > MAX_IOVEC) {
		ODP_ERR("Buffer is too big to construct an iovec!\n");
		return -1;
	}

	int to_map = (int)buf_size - (int)buf_offset;
	int to_offset = buf_offset;
	memset(iov, 0, sizeof(struct iovec)*MAX_IOVEC);

	// Fast forward to the offset in the buffer
	i = 0;
	while (to_offset > 0) {
		to_offset -= (int)segment_size;

		if (to_offset < 0) {
			break;
		} else if ((++i % ODP_BUFFER_MAX_SEG) == 0) {
			segs = segs->next_segs;
		}
	}

	// If we're in the middle of a buffer
	if (to_offset < 0) {
		iov[j].iov_base = (char*)segs->addr[(i % ODP_BUFFER_MAX_SEG)] +
			(to_offset + (int)segment_size);
		iov[j].iov_len = -to_offset;

		j++;
		i++;
		to_map += to_offset;
	}

	// Loop around the buffer segments
	while (to_map > 0) {
		iov[j].iov_base = segs->addr[(i % ODP_BUFFER_MAX_SEG)];
		iov[j].iov_len = (to_map < segment_size) ? to_map : segment_size;

		to_map -= (to_map < segment_size) ? to_map : segment_size;
		if ((++i % ODP_BUFFER_MAX_SEG) == 0) {
			segs = segs->next_segs;
		}
		j++;
	}
	ODP_ASSERT(to_map == 0 );
	ODP_ASSERT(j == (buf_size - buf_offset / segment_size) || 
		   j - 1 == (buf_size - buf_offset / segment_size));
	return j;
}

// Update our iocb to be resubbed to libaio.  Need to clean this code up some
void reenqueue_ioop(odp_buffer_t fileio_cmd, odp_fileio_cmd_t *cmd, fileio_queue *fioq)
{
	void *buffer = odp_buffer_addr(cmd->buffer);
	odp_buffer_t new_iov_buf = ODP_BUFFER_INVALID;
	struct iocb *cbs[1];
	struct iovec *iov;
	int num_iovs;
	cbs[0] = (struct iocb*)odp_buffer_addr(cmd->iocb);

	if (cmd->cmd == ODP_FILEIO_READ) {
		if (cmd->iov_buf == ODP_BUFFER_INVALID) {
			io_prep_pread(cbs[0], cmd->fd, buffer, cmd->size - cmd->status,
				      cmd->fd_offset + cmd->status);
		} else {
			new_iov_buf = odp_buffer_alloc(ioqs.iov_pool);
			if (new_iov_buf == ODP_BUFFER_INVALID) {
				ODP_ERR("Ran out of iov_bufs!\n");
				ODP_ASSERT(0);
			}
			iov = odp_buffer_addr(new_iov_buf);
			num_iovs = create_iov_list_from_buffer(cmd->buffer, iov,
							       cmd->size,
							       cmd->status);
			io_prep_preadv(cbs[0], cmd->fd, iov, num_iovs,
				       cmd->fd_offset + cmd->status);
			odp_buffer_free(cmd->iov_buf);
			cmd->iov_buf = new_iov_buf;
		}
		io_set_eventfd(cbs[0], fioq->cmpl_evtfd);
		cbs[0]->data = (void*)fileio_cmd;
	} else if (cmd->cmd == ODP_FILEIO_WRITE) {
		if (cmd->iov_buf == ODP_BUFFER_INVALID) {
			io_prep_pwrite(cbs[0], cmd->fd, buffer, cmd->size - cmd->status,
				       cmd->fd_offset + cmd->status);
		} else {
			new_iov_buf = odp_buffer_alloc(ioqs.iov_pool);
			if (new_iov_buf == ODP_BUFFER_INVALID) {
				ODP_ERR("Ran out of iov_bufs!\n");
				ODP_ASSERT(0);
			}
			iov = odp_buffer_addr(new_iov_buf);
			num_iovs = create_iov_list_from_buffer(cmd->buffer, iov,
							       cmd->size,
							       cmd->status);
			io_prep_pwritev(cbs[0], cmd->fd, iov, num_iovs,
				       cmd->fd_offset + cmd->status);
			odp_buffer_free(cmd->iov_buf);
			cmd->iov_buf = new_iov_buf;

		}

		io_set_eventfd(cbs[0], fioq->cmpl_evtfd);
		cbs[0]->data = (void*)fileio_cmd;
	}
	// Submit io op here
	int res = io_submit(fioq->aio_ctx, 1, cbs);
	if (res < 1) {
		ODP_ERR("io_submit resubmit failed - %d\n", res);
		ODP_ASSERT(0);
	}
}
