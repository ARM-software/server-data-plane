/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp/api/align.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/buffer.h>
#include <odp/api/pool.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/thread.h>
#include <odp/api/time.h>
#include <odp/api/spinlock.h>
#include <odp/api/hints.h>
#include <odp/api/cpu.h>
#include <odp/api/epoll.h>

#include <odp_fileio_internal.h>
#include <odp_queue_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_socket_io_internal.h>
#include <odp/api/thrmask.h>
#include <odp_config_internal.h>
#include <odp_schedule_internal.h>
#include <odp_schedule_ordered_internal.h>
#ifdef _ODP_PKTIO_IPC
#include <odp_pool_internal.h>
#endif

/* Number of priority levels  */
#define NUM_PRIO 8

ODP_STATIC_ASSERT(ODP_SCHED_PRIO_LOWEST == (NUM_PRIO - 1),
		  "lowest_prio_does_not_match_with_num_prios");

ODP_STATIC_ASSERT((ODP_SCHED_PRIO_NORMAL > 0) &&
		  (ODP_SCHED_PRIO_NORMAL < (NUM_PRIO - 1)),
		  "normal_prio_is_not_between_highest_and_lowest");

/* Number of scheduling groups */
#define NUM_SCHED_GRPS 256

/* Priority queues per priority */
#define QUEUES_PER_PRIO  4

/* Packet input poll cmd queues */
#define POLL_CMD_QUEUES  4

/* Maximum number of packet input queues per command */
#define MAX_PKTIN 8

/* Maximum number of packet IO interfaces */
#define NUM_PKTIO ODP_CONFIG_PKTIO_ENTRIES

/* Mask of queues per priority */
typedef uint16_t pri_mask_t;

ODP_STATIC_ASSERT((8 * sizeof(pri_mask_t)) >= QUEUES_PER_PRIO,
		  "pri_mask_t_is_too_small");

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

typedef struct {
	odp_queue_t    pri_queue[NUM_PRIO][QUEUES_PER_PRIO];
	pri_mask_t     pri_mask[NUM_PRIO];
	odp_spinlock_t mask_lock;

	odp_spinlock_t poll_cmd_lock;
	struct {
		odp_queue_t queue;
		uint16_t    num;
	} poll_cmd[POLL_CMD_QUEUES];

	odp_pool_t     pool;
	odp_shm_t      shm;
	uint32_t       pri_count[NUM_PRIO][QUEUES_PER_PRIO];

	odp_spinlock_t grp_lock;
	odp_thrmask_t mask_all;
	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN];
		odp_thrmask_t  mask;
	} sched_grp[NUM_SCHED_GRPS];

	struct {
		odp_event_t cmd_ev;
		odp_queue_t pri_queue;
		int         prio;
	} queue[ODP_CONFIG_QUEUES];

	struct {
		odp_event_t cmd_ev;
		int fd;
		uint32_t epoll_events;
	} sockio[ODP_CONFIG_SOCKIO_ENTRIES];

	struct {
		odp_event_t cmd_ev[3];
		int fd[3];
		uint32_t epoll_events[3];
	} fileio[ODP_CONFIG_FILEIO_QS];

	struct {
		int         num;
	} pktio[NUM_PKTIO];

} sched_global_t;

/* Schedule command */
typedef struct {
	int           cmd;

	union {
		struct {
			uint32_t      queue_index;
		};

		struct {
			int           pktio_index;
			int           num;
			int           index[MAX_PKTIN];
		};

		struct {
			//odp_sockio_t sockio;
			//sockio_entry_t *se;
			uint32_t sockio_idx;
		};

		struct {
			//fileio_queue *fioq;
			uint32_t fioq_idx;
			uint32_t sched_idx;
		};
	};
} sched_cmd_t;

#define SCHED_CMD_DEQUEUE    0
#define SCHED_CMD_POLL_PKTIN 1
#define SCHED_CMD_POLL_SOCKIN 2
#define SCHED_CMD_POLL_FILEIO_SUB 3
#define SCHED_CMD_POLL_FILEIO_CMPL 4
#define SCHED_CMD_POLL_FILEIO_TIMER 5

/* Global scheduler context */
static sched_global_t *sched;

/* Thread local scheduler context */
__thread sched_local_t sched_local;

static void sched_local_init(void)
{
	memset(&sched_local, 0, sizeof(sched_local_t));

	sched_local.thr       = odp_thread_id();
	sched_local.pri_queue = ODP_QUEUE_INVALID;
	sched_local.queue     = ODP_QUEUE_INVALID;
	sched_local.cmd_ev    = ODP_EVENT_INVALID;
}

static int schedule_init_global(void)
{
	odp_shm_t shm;
	odp_pool_t pool;
	int i, j;
	odp_pool_param_t params;
	int num_cmd;

	ODP_DBG("Schedule init ... ");

	shm = odp_shm_reserve("odp_scheduler",
			      sizeof(sched_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	sched = odp_shm_addr(shm);

	if (sched == NULL) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	memset(sched, 0, sizeof(sched_global_t));

	/* Number of schedule commands.
	 * One per scheduled queue and packet interface */
	num_cmd = sched_cb_num_queues() + sched_cb_num_pktio();

	odp_pool_param_init(&params);
	params.buf.size  = sizeof(sched_cmd_t);
	params.buf.align = 0;
	params.buf.num   = num_cmd;
	params.type      = ODP_POOL_BUFFER;

#ifdef _ODP_PKTIO_IPC
	pool = _pool_create("odp_sched_pool", &params, 0);
#else
	pool = odp_pool_create("odp_sched_pool", &params);
#endif
	if (pool == ODP_POOL_INVALID) {
		ODP_ERR("Schedule init: Pool create failed.\n");
		return -1;
	}

	sched->pool = pool;
	sched->shm  = shm;
	odp_spinlock_init(&sched->mask_lock);

	for (i = 0; i < NUM_PRIO; i++) {
		odp_queue_t queue;
		char name[] = "odp_priXX_YY";

		name[7] = '0' + i / 10;
		name[8] = '0' + i - 10*(i / 10);

		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			name[10] = '0' + j / 10;
			name[11] = '0' + j - 10*(j / 10);

			queue = odp_queue_create(name, NULL);

			if (queue == ODP_QUEUE_INVALID) {
				ODP_ERR("Sched init: Queue create failed.\n");
				return -1;
			}

			sched->pri_queue[i][j] = queue;
			sched->pri_mask[i]     = 0;
		}
	}

	odp_spinlock_init(&sched->poll_cmd_lock);
	for (i = 0; i < POLL_CMD_QUEUES; i++) {
		odp_queue_t queue;
		char name[] = "odp_poll_cmd_YY";

		name[13] = '0' + i / 10;
		name[14] = '0' + i - 10 * (i / 10);

		queue = odp_queue_create(name, NULL);

		if (queue == ODP_QUEUE_INVALID) {
			ODP_ERR("Sched init: Queue create failed.\n");
			return -1;
		}

		sched->poll_cmd[i].queue = queue;
	}

	odp_spinlock_init(&sched->grp_lock);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		odp_thrmask_zero(&sched->sched_grp[i].mask);
	}

	odp_thrmask_setall(&sched->mask_all);

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		sched->queue[i].cmd_ev    = ODP_EVENT_INVALID;
		sched->queue[i].pri_queue = ODP_QUEUE_INVALID;
	}

	ODP_DBG("done\n");

	return 0;
}

static int schedule_term_global(void)
{
	int ret = 0;
	int rc = 0;
	int i, j;
	odp_event_t  ev;

	for (i = 0; i < NUM_PRIO; i++) {
		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			odp_queue_t  pri_q;

			pri_q = sched->pri_queue[i][j];

			while ((ev = odp_queue_deq(pri_q)) !=
			      ODP_EVENT_INVALID) {
				odp_buffer_t buf;
				sched_cmd_t *sched_cmd;
				uint32_t qi;
				odp_event_t events[1];
				int num;

				buf = odp_buffer_from_event(ev);
				sched_cmd = odp_buffer_addr(buf);
				qi  = sched_cmd->queue_index;
				num = sched_cb_queue_deq_multi(qi, events, 1);

				if (num < 0)
					sched_cb_queue_destroy_finalize(qi);

				if (num > 0)
					ODP_ERR("Queue not empty\n");
			}

			if (odp_queue_destroy(pri_q)) {
				ODP_ERR("Pri queue destroy fail.\n");
				rc = -1;
			}
		}
	}

	for (i = 0; i < POLL_CMD_QUEUES; i++) {
		odp_queue_t queue = sched->poll_cmd[i].queue;

		while ((ev = odp_queue_deq(queue)) != ODP_EVENT_INVALID)
			odp_event_free(ev);

		if (odp_queue_destroy(queue)) {
			ODP_ERR("Poll cmd queue destroy failed\n");
			rc = -1;
		}
	}

	if (odp_pool_destroy(sched->pool) != 0) {
		ODP_ERR("Pool destroy fail.\n");
		rc = -1;
	}

	ret = odp_shm_free(sched->shm);
	if (ret < 0) {
		ODP_ERR("Shm free failed for odp_scheduler");
		rc = -1;
	}

	return rc;
}

static int schedule_init_local(void)
{
	sched_local_init();
	return 0;
}

static inline void schedule_release_context(void)
{
	if (sched_local.origin_qe != NULL) {
		release_order(sched_local.origin_qe, sched_local.order,
			      sched_local.pool, sched_local.enq_called);
		sched_local.origin_qe = NULL;
	} else
		odp_schedule_release_atomic();
}

static int schedule_term_local(void)
{
	if (sched_local.num) {
		ODP_ERR("Locally pre-scheduled events exist.\n");
		return -1;
	}

	schedule_release_context();

	sched_local_init();
	return 0;
}

static inline int pri_id_queue(uint32_t queue_index)
{
	return ((QUEUES_PER_PRIO - 1) & queue_index);
}

static odp_queue_t pri_set(int id, int prio)
{
	odp_spinlock_lock(&sched->mask_lock);
	sched->pri_mask[prio] |= 1 << id;
	sched->pri_count[prio][id]++;
	odp_spinlock_unlock(&sched->mask_lock);

	return sched->pri_queue[prio][id];
}

static void pri_clr(int id, int prio)
{
	odp_spinlock_lock(&sched->mask_lock);

	/* Clear mask bit when last queue is removed*/
	sched->pri_count[prio][id]--;

	if (sched->pri_count[prio][id] == 0)
		sched->pri_mask[prio] &= (uint8_t)(~(1 << id));

	odp_spinlock_unlock(&sched->mask_lock);
}

static odp_queue_t pri_set_queue(uint32_t queue_index, int prio)
{
	int id = pri_id_queue(queue_index);

	return pri_set(id, prio);
}

static void pri_clr_queue(uint32_t queue_index, int prio)
{
	int id = pri_id_queue(queue_index);
	pri_clr(id, prio);
}

static int schedule_init_queue(uint32_t queue_index,
			       const odp_schedule_param_t *sched_param)
{
	odp_buffer_t buf;
	sched_cmd_t *sched_cmd;
	int prio = sched_param->prio;

	buf = odp_buffer_alloc(sched->pool);

	if (buf == ODP_BUFFER_INVALID)
		return -1;

	sched_cmd        = odp_buffer_addr(buf);
	sched_cmd->cmd   = SCHED_CMD_DEQUEUE;
	sched_cmd->queue_index = queue_index;

	sched->queue[queue_index].cmd_ev = odp_buffer_to_event(buf);
	sched->queue[queue_index].pri_queue = pri_set_queue(queue_index, prio);
	sched->queue[queue_index].prio = prio;

	return 0;
}

static int schedule_sockio_init(uint32_t sockio_idx, int fd, uint32_t epoll_events)
{
	odp_buffer_t buf;
	sched_cmd_t *sched_cmd;
	buf = odp_buffer_alloc(sched->pool);

	if (buf == ODP_BUFFER_INVALID)
		return -1;

	sched_cmd = odp_buffer_addr(buf);
	sched_cmd->cmd = SCHED_CMD_POLL_SOCKIN;
	sched_cmd->sockio_idx = sockio_idx;

	sched->sockio[sockio_idx].cmd_ev = odp_buffer_to_event(buf);
	sched->sockio[sockio_idx].fd = fd;
	sched->sockio[sockio_idx].epoll_events = epoll_events;

	return 0;
}

static int schedule_sockio_start(uint32_t sockio_idx, int fd, uint32_t epoll_events)
{
	/* This should not change */
	ODP_ASSERT(fd = sched->sockio[sockio_idx].fd);
	sched->sockio[sockio_idx].epoll_events = epoll_events;

	if (odp_epoll_set_event(sched->sockio[sockio_idx].cmd_ev,
				sched->sockio[sockio_idx].fd,
				sched->sockio[sockio_idx].epoll_events)) {
		ODP_ASSERT("Setting sockio cmd_ev failed in epoll!\n");
	}
	return 0;
}

static int schedule_sockio_reset(uint32_t sockio_idx, int fd, uint32_t epoll_events)
{
	/* This should not change */
	ODP_ASSERT(fd = sched->sockio[sockio_idx].fd);
	sched->sockio[sockio_idx].epoll_events = epoll_events;

	if (odp_epoll_reset_event(sched->sockio[sockio_idx].cmd_ev,
				  sched->sockio[sockio_idx].fd,
				  sched->sockio[sockio_idx].epoll_events)) {
		ODP_ASSERT("Setting sockio cmd_ev failed in epoll!\n");
	}
	return 0;
}

static int schedule_fileioq_init(uint32_t fileio_index, int fd,
			  uint32_t epoll_events, int sched_idx)
{
	odp_buffer_t buf;
	sched_cmd_t *sched_cmd;
	buf = odp_buffer_alloc(sched->pool);

	if (buf == ODP_BUFFER_INVALID)
		return -1;

	sched_cmd = odp_buffer_addr(buf);
	switch (sched_idx) {
	case 0:
		sched_cmd->cmd = SCHED_CMD_POLL_FILEIO_SUB;
		break;
	case 1:
		sched_cmd->cmd = SCHED_CMD_POLL_FILEIO_CMPL;
		break;
	case 2:
		sched_cmd->cmd = SCHED_CMD_POLL_FILEIO_TIMER;
		break;
	default:
		break;
	}
	sched_cmd->fioq_idx = fileio_index;
	sched_cmd->sched_idx = sched_idx;
	sched->fileio[fileio_index].cmd_ev[sched_idx] = odp_buffer_to_event(buf);
	sched->fileio[fileio_index].fd[sched_idx] = fd;
	sched->fileio[fileio_index].epoll_events[sched_idx] = epoll_events;

	return 0;
}

static int schedule_fileioq_start(uint32_t fileio_idx, int fd,
			   uint32_t epoll_events, int sched_idx)
{
	/* This should not change */
	ODP_ASSERT(fd = sched->fileio[fileio_idx].fd[sched_idx]);
	sched->fileio[fileio_idx].epoll_events[sched_idx] = epoll_events;

	if (odp_epoll_set_event(sched->fileio[fileio_idx].cmd_ev[sched_idx],
				sched->fileio[fileio_idx].fd[sched_idx],
				sched->fileio[fileio_idx].epoll_events[sched_idx])) {
		ODP_ASSERT("Setting fileio cmd_ev failed in epoll!\n");
	}
	return 0;
}

static int schedule_fileioq_reset(uint32_t fileio_idx, int fd,
			   uint32_t epoll_events, int sched_idx)
{
	/* This should not change */
	ODP_ASSERT(fd = sched->fileio[fileio_idx].fd[sched_idx]);
	sched->fileio[fileio_idx].epoll_events[sched_idx] = epoll_events;

	if (odp_epoll_reset_event(sched->fileio[fileio_idx].cmd_ev[sched_idx],
				  sched->fileio[fileio_idx].fd[sched_idx],
				  sched->fileio[fileio_idx].epoll_events[sched_idx])) {
		ODP_ASSERT("Setting fileio cmd_ev failed in epoll!\n");
	}
	return 0;
}

static void schedule_destroy_queue(uint32_t queue_index)
{
	int prio = sched->queue[queue_index].prio;

	odp_event_free(sched->queue[queue_index].cmd_ev);

	pri_clr_queue(queue_index, prio);

	sched->queue[queue_index].cmd_ev    = ODP_EVENT_INVALID;
	sched->queue[queue_index].pri_queue = ODP_QUEUE_INVALID;
	sched->queue[queue_index].prio      = 0;
}

static int poll_cmd_queue_idx(int pktio_index, int in_queue_idx)
{
	return (POLL_CMD_QUEUES - 1) & (pktio_index ^ in_queue_idx);
}

static void schedule_pktio_start(int pktio_index, int num_in_queue,
				 int in_queue_idx[])
{
	odp_buffer_t buf;
	sched_cmd_t *sched_cmd;
	odp_queue_t queue;
	int i, idx;

	if (num_in_queue > MAX_PKTIN)
		ODP_ABORT("Too many input queues for scheduler\n");

	sched->pktio[pktio_index].num = num_in_queue;

	/* Create a pktio poll command per queue */
	for (i = 0; i < num_in_queue; i++) {
		buf = odp_buffer_alloc(sched->pool);

		if (buf == ODP_BUFFER_INVALID)
			ODP_ABORT("Sched pool empty\n");

		sched_cmd        = odp_buffer_addr(buf);
		sched_cmd->cmd   = SCHED_CMD_POLL_PKTIN;
		sched_cmd->pktio_index = pktio_index;
		sched_cmd->num   = 1;
		sched_cmd->index[0] = in_queue_idx[i];

		idx = poll_cmd_queue_idx(pktio_index, in_queue_idx[i]);

		odp_spinlock_lock(&sched->poll_cmd_lock);
		sched->poll_cmd[idx].num++;
		odp_spinlock_unlock(&sched->poll_cmd_lock);

		queue = sched->poll_cmd[idx].queue;

		if (odp_queue_enq(queue, odp_buffer_to_event(buf)))
			ODP_ABORT("schedule_pktio_start failed\n");
	}
}

static int schedule_pktio_stop(sched_cmd_t *sched_cmd)
{
	int num;
	int pktio_index = sched_cmd->pktio_index;
	int idx = poll_cmd_queue_idx(pktio_index, sched_cmd->index[0]);

	odp_spinlock_lock(&sched->poll_cmd_lock);
	sched->poll_cmd[idx].num--;
	sched->pktio[pktio_index].num--;
	num = sched->pktio[pktio_index].num;
	odp_spinlock_unlock(&sched->poll_cmd_lock);

	return num;
}

static void schedule_release_atomic(void)
{
	if (sched_local.pri_queue != ODP_QUEUE_INVALID &&
	    sched_local.num       == 0) {
		/* Release current atomic queue */
		if (odp_queue_enq(sched_local.pri_queue, sched_local.cmd_ev))
			ODP_ABORT("odp_schedule_release_atomic failed\n");
		sched_local.pri_queue = ODP_QUEUE_INVALID;
	}
}

static void schedule_release_ordered(void)
{
	if (sched_local.origin_qe) {
		int rc = release_order(sched_local.origin_qe,
				       sched_local.order,
				       sched_local.pool,
				       sched_local.enq_called);
		if (rc == 0)
			sched_local.origin_qe = NULL;
	}
}

static inline int copy_events(odp_event_t out_ev[], unsigned int max)
{
	int i = 0;

	while (sched_local.num && max) {
		out_ev[i] = sched_local.ev_stash[sched_local.index];
		sched_local.index++;
		sched_local.num--;
		max--;
		i++;
	}

	return i;
}

/*
 * Schedule queues
 */
static int do_schedule(odp_queue_t *out_queue, odp_event_t out_ev[],
		       unsigned int max_num, unsigned int max_deq)
{
	int i, j;
	int ret;
	int id;
	odp_event_t ev;
	odp_buffer_t buf;
	sched_cmd_t *sched_cmd;
	int offset = 0;
	uint32_t qi;

	/* Epoll functionality */
	odp_event_t epoll_evts[ODP_MAX_EPOLL_EVENTS];
	int num_evts;

	// Make it so we don't dequeue more than what is asked for...
	// XXX Not sure if this a proper optimization
	if (max_num < max_deq) { 
		max_deq = max_num;
	}

	if (sched_local.num) {
		ret = copy_events(out_ev, max_num);

		if (out_queue)
			*out_queue = sched_local.queue;

		return ret;
	}

	schedule_release_context();

	if (odp_unlikely(sched_local.pause))
		return 0;

	/* Each thread prefers a priority queue. This offset avoids starvation
	 * of other priority queues on low thread counts. */
	if (odp_unlikely((sched_local.round & 0x3f) == 0)) {
		offset = sched_local.prefer_offset;
		sched_local.prefer_offset = (offset + 1) &
					    (QUEUES_PER_PRIO - 1);
	}

	sched_local.round++;

	/* Schedule events */
	for (i = 0; i < NUM_PRIO; i++) {

		if (sched->pri_mask[i] == 0)
			continue;

		id = (sched_local.thr + offset) & (QUEUES_PER_PRIO - 1);

		for (j = 0; j < QUEUES_PER_PRIO; j++, id++) {
			odp_queue_t  pri_q;
			int num;
			int grp;
			int ordered;
			odp_queue_t handle;

			if (id >= QUEUES_PER_PRIO)
				id = 0;

			if (odp_unlikely((sched->pri_mask[i] & (1 << id)) == 0))
				continue;

			pri_q = sched->pri_queue[i][id];
			ev    = odp_queue_deq(pri_q);

			if (ev == ODP_EVENT_INVALID)
				continue;

			buf       = odp_buffer_from_event(ev);
			sched_cmd = odp_buffer_addr(buf);
			qi        = sched_cmd->queue_index;
			grp       = sched_cb_queue_grp(qi);

			if (grp > ODP_SCHED_GROUP_ALL &&
			    !odp_thrmask_isset(&sched->sched_grp[grp].mask,
					       sched_local.thr)) {
				/* This thread is not eligible for work from
				 * this queue, so continue scheduling it.
				 */
				if (odp_queue_enq(pri_q, ev))
					ODP_ABORT("schedule failed\n");
				continue;
			}

			ordered = sched_cb_queue_is_ordered(qi);

			/* For ordered queues we want consecutive events to
			 * be dispatched to separate threads, so do not cache
			 * them locally.
			 */
			if (ordered)
				max_deq = 1;

			/* Call the queue entry's dequeue_multi function so this
			 * works with all queue types.
			 */ 
			num = sched_cb_queue_deq_multi(qi, sched_local.ev_stash,
						       max_deq);

			if (num < 0) {
				/* Destroyed queue */
				sched_cb_queue_destroy_finalize(qi);
				continue;
			}

			if (num == 0) {
				continue;
			}

			handle            = sched_cb_queue_handle(qi);
			sched_local.num   = num;
			sched_local.index = 0;
			sched_local.queue = handle;
			ret = copy_events(out_ev, max_num);

			if (ordered) {
				/* Continue scheduling ordered queues */
				if (odp_queue_enq(pri_q, ev))
					ODP_ABORT("schedule failed\n");

				/* Cache order info about this event */
				cache_order_info(qi);
			} else if (sched_cb_queue_is_atomic(qi)) {
				/* Hold queue during atomic access */
				sched_local.pri_queue = pri_q;
				sched_local.cmd_ev    = ev;
			} else {
				/* Continue scheduling the queue */
				if (odp_queue_enq(pri_q, ev))
					ODP_ABORT("schedule failed\n");
			}

			/* Output the source queue handle */
			if (out_queue)
				*out_queue = handle;

			return ret;
		}
	}

	/* Get any ready sockio and fileio's from epoll and read their data into
	 * events to place on the event queues themselves. If we 
	 * end up doing classification on Layer7, then this makes more
	 * sense.
	 */
	if (odp_thread_type() == ODP_THREAD_IO_WORKER) {
		num_evts = odp_epoll_get_events(epoll_evts,
						ODP_MIN_EPOLL_EVENTS,
						ODP_EPOLL_BLOCK);
		int num_pkts = 4*ODP_SOCKET_MAX_BURST;
		if (num_evts > 0) {
			odp_event_t  ev;
			sched_cmd_t *sched_cmd;
			odp_buffer_hdr_t *hdr;
			do {
				for (i = 0; i < num_evts; i++) {
					ev = epoll_evts[i];
					hdr = odp_buf_to_hdr(odp_buffer_from_event(ev));
					sched_cmd = odp_buffer_addr(odp_buffer_from_event(ev));
					if (hdr->next != NULL) {
						ODP_ABORT("double posting events!\n");
					}
					int cmd = sched_cmd->cmd;

					switch (cmd) {
					case SCHED_CMD_POLL_SOCKIN:
						num_pkts -=
							sockin_poll(sched_cmd->sockio_idx);
						break;
					case SCHED_CMD_POLL_FILEIO_SUB:
						num_pkts -=
							submit_fileio_ops(sched_cmd->fioq_idx);
						break;
					case SCHED_CMD_POLL_FILEIO_CMPL:
						num_pkts -=
							sweep_fileio_completions(sched_cmd->fioq_idx);
						break;
					case SCHED_CMD_POLL_FILEIO_TIMER:
						num_pkts -=
							add_tokens_on_tick(sched_cmd->fioq_idx);
						break;
					default:
						ODP_ERR("Got a bad epoll in scheduling loop!\n");
						break;
					}
				}
				// Keep getting events until we sweep enough packets or nothing to do
				num_evts = 0;
				if (num_pkts > 0) {
					num_evts = odp_epoll_get_events(epoll_evts,
									ODP_MAX_EPOLL_EVENTS,
									ODP_EPOLL_NOBLOCK);
				}
			} while (num_evts > 0 && num_pkts > 0);
		}
	} // else -- need some way to let cores just wait and not spin here, but 
	  //         for now, all threads will be IO_WORKERs initially

	/*
	 * Poll packet input when there are no events
	 *   * Each thread starts the search for a poll command from its
	 *     preferred command queue. If the queue is empty, it moves to other
	 *     queues.
	 *   * Most of the times, the search stops on the first command found to
	 *     optimize multi-threaded performance. A small portion of polls
	 *     have to do full iteration to avoid packet input starvation when
	 *     there are less threads than command queues.
	 */
	id = sched_local.thr & (POLL_CMD_QUEUES - 1);

	for (i = 0; i < POLL_CMD_QUEUES; i++, id++) {
		odp_queue_t cmd_queue;
		int pktio_index;

		if (id == POLL_CMD_QUEUES)
			id = 0;

		if (sched->poll_cmd[id].num == 0)
			continue;

		cmd_queue = sched->poll_cmd[id].queue;
		ev = odp_queue_deq(cmd_queue);

		if (ev == ODP_EVENT_INVALID)
			continue;

		buf       = odp_buffer_from_event(ev);
		sched_cmd = odp_buffer_addr(buf);

		if (sched_cmd->cmd != SCHED_CMD_POLL_PKTIN)
			ODP_ABORT("Bad poll command\n");

		pktio_index = sched_cmd->pktio_index;

		/* Poll packet input */
		if (sched_cb_pktin_poll(pktio_index,
					sched_cmd->num,
					sched_cmd->index)) {
			/* Pktio stopped or closed. Remove poll command and call
			 * stop_finalize when all commands of the pktio has
			 * been removed. */
			if (schedule_pktio_stop(sched_cmd) == 0)
				sched_cb_pktio_stop_finalize(pktio_index);

			odp_buffer_free(buf);
		} else {
			/* Continue scheduling the pktio */
			if (odp_queue_enq(cmd_queue, ev))
				ODP_ABORT("Poll command enqueue failed\n");

			/* Do not iterate through all pktin poll command queues
			 * every time. */
			if (odp_likely(sched_local.pktin_polls & 0xf))
				break;
		}
	}

	sched_local.pktin_polls++;
	return 0;
}


static int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
			 odp_event_t out_ev[],
			 unsigned int max_num, unsigned int max_deq)
{
	odp_time_t next, wtime;
	int first = 1;
	int ret;

	while (1) {
		ret = do_schedule(out_queue, out_ev, max_num, max_deq);

		if (ret)
			break;

		if (wait == ODP_SCHED_WAIT)
			continue;

		if (wait == ODP_SCHED_NO_WAIT)
			break;

		if (first) {
			wtime = odp_time_local_from_ns(wait);
			next = odp_time_sum(odp_time_local(), wtime);
			first = 0;
			continue;
		}

		if (odp_time_cmp(next, odp_time_local()) < 0)
			break;
	}

	return ret;
}

static odp_event_t schedule(odp_queue_t *out_queue, uint64_t wait)
{
	odp_event_t ev;

	ev = ODP_EVENT_INVALID;

	schedule_loop(out_queue, wait, &ev, 1, MAX_DEQ);

	return ev;
}

static int schedule_multi(odp_queue_t *out_queue, uint64_t wait,
			  odp_event_t events[], int num)
{
	return schedule_loop(out_queue, wait, events, num, MAX_DEQ);
}

static void schedule_pause(void)
{
	sched_local.pause = 1;
}

static void schedule_resume(void)
{
	sched_local.pause = 0;
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static int schedule_num_prio(void)
{
	return NUM_PRIO;
}

static odp_schedule_group_t schedule_group_create(const char *name,
						  const odp_thrmask_t *mask)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_spinlock_lock(&sched->grp_lock);

	for (i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (sched->sched_grp[i].name[0] == 0) {
			strncpy(sched->sched_grp[i].name, name,
				ODP_SCHED_GROUP_NAME_LEN - 1);
			odp_thrmask_copy(&sched->sched_grp[i].mask, mask);
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return group;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		odp_thrmask_zero(&sched->sched_grp[group].mask);
		memset(sched->sched_grp[group].name, 0,
		       ODP_SCHED_GROUP_NAME_LEN);
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_spinlock_lock(&sched->grp_lock);

	for (i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (strcmp(name, sched->sched_grp[i].name) == 0) {
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return group;
}

static int schedule_group_join(odp_schedule_group_t group,
			       const odp_thrmask_t *mask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		odp_thrmask_or(&sched->sched_grp[group].mask,
			       &sched->sched_grp[group].mask,
			       mask);
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_group_leave(odp_schedule_group_t group,
				const odp_thrmask_t *mask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		odp_thrmask_t leavemask;

		odp_thrmask_xor(&leavemask, mask, &sched->mask_all);
		odp_thrmask_and(&sched->sched_grp[group].mask,
				&sched->sched_grp[group].mask,
				&leavemask);
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *thrmask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		*thrmask = sched->sched_grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    sched->sched_grp[group].name[0] != 0) {
		info->name    = sched->sched_grp[group].name;
		info->thrmask = sched->sched_grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

static int schedule_thr_add(odp_schedule_group_t group, int thr)
{
	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_spinlock_lock(&sched->grp_lock);

	odp_thrmask_set(&sched->sched_grp[group].mask, thr);

	odp_spinlock_unlock(&sched->grp_lock);

	return 0;
}

static int schedule_thr_rem(odp_schedule_group_t group, int thr)
{
	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_spinlock_lock(&sched->grp_lock);

	odp_thrmask_clr(&sched->sched_grp[group].mask, thr);

	odp_spinlock_unlock(&sched->grp_lock);

	return 0;
}

/* This function is a no-op */
static void schedule_prefetch(int num ODP_UNUSED)
{
}

static int schedule_sched_queue(uint32_t queue_index)
{
	odp_queue_t pri_queue = sched->queue[queue_index].pri_queue;
	odp_event_t cmd_ev    = sched->queue[queue_index].cmd_ev;

	sched_local.ignore_ordered_context = 1;
	return odp_queue_enq(pri_queue, cmd_ev);
}

static int schedule_num_grps(void)
{
	return NUM_SCHED_GRPS;
}

/* Fill in scheduler interface */
const schedule_fn_t schedule_default_fn = {
	.pktio_start = schedule_pktio_start,
	.thr_add = schedule_thr_add,
	.thr_rem = schedule_thr_rem,
	.num_grps = schedule_num_grps,
	.init_queue = schedule_init_queue,
	.destroy_queue = schedule_destroy_queue,
	.sched_queue = schedule_sched_queue,
	.init_sockio = schedule_sockio_init,
	.start_sockio = schedule_sockio_start,
	.reset_sockio = schedule_sockio_reset,
	.init_fileio = schedule_fileioq_init,
	.start_fileio = schedule_fileioq_start,
	.reset_fileio = schedule_fileioq_reset,
	.ord_enq = schedule_ordered_queue_enq,
	.ord_enq_multi = schedule_ordered_queue_enq_multi,
	.init_global = schedule_init_global,
	.term_global = schedule_term_global,
	.init_local  = schedule_init_local,
	.term_local  = schedule_term_local
};

/* Fill in scheduler API calls */
const schedule_api_t schedule_default_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule                 = schedule,
	.schedule_multi           = schedule_multi,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_num_prio        = schedule_num_prio,
	.schedule_group_create    = schedule_group_create,
	.schedule_group_destroy   = schedule_group_destroy,
	.schedule_group_lookup    = schedule_group_lookup,
	.schedule_group_join      = schedule_group_join,
	.schedule_group_leave     = schedule_group_leave,
	.schedule_group_thrmask   = schedule_group_thrmask,
	.schedule_group_info      = schedule_group_info,
	.schedule_order_lock      = schedule_order_lock,
	.schedule_order_unlock    = schedule_order_unlock
};
