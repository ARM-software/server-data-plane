/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/queue.h>
#include <odp_queue_internal.h>
#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp_config_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_socket_io_internal.h>
#include <odp_socket_io_queue.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/sync.h>
#include <odp/api/traffic_mngr.h>
#include <odp_schedule_ordered_internal.h>

#define NUM_INTERNAL_QUEUES 64

#ifdef USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#define LOCK_TRY(a)  odp_ticketlock_trylock(a)
#elif defined(USE_PTHREADLOCK)
#include <odp/pthreadlock.h>
#define LOCK(a)      odp_pthreadlock_lock(a)
#define UNLOCK(a)    odp_pthreadlock_unlock(a)
#define LOCK_INIT(a) odp_pthreadlock_init(a)
#define LOCK_TRY(a)  odp_pthreadlock_trylock(a)
#else
#include <odp/api/spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#define LOCK_TRY(a)  odp_spinlock_trylock(a)
#endif

#include <assert.h>
#include <string.h>
#include <inttypes.h>

typedef struct queue_table_t {
	queue_entry_t  queue[ODP_CONFIG_QUEUES];
} queue_table_t;

static queue_table_t *queue_tbl;

static inline odp_queue_t queue_from_id(uint32_t queue_id)
{
	return _odp_cast_scalar(odp_queue_t, queue_id + 1);
}

static inline int queue_is_atomic(queue_entry_t *qe)
{
	return qe->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC;
}

static inline int queue_is_ordered(queue_entry_t *qe)
{
	return qe->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED;
}

static inline void queue_add(queue_entry_t *queue,
			     odp_buffer_hdr_t *buf_hdr)
{
	buf_hdr->next = NULL;

	if (queue->s.head)
		queue->s.tail->next = buf_hdr;
	else
		queue->s.head = buf_hdr;

	queue->s.tail = buf_hdr;
}

static inline void queue_pre(queue_entry_t *queue,
                             odp_buffer_hdr_t *buf_hdr)
{
        if (queue->s.head) {
                buf_hdr->next = queue->s.head;
                queue->s.head = buf_hdr;
        } else {
                queue->s.head = buf_hdr;
                queue->s.tail =	buf_hdr;
                buf_hdr->next =	NULL;
	}
}

queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param)
{
	strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);

	memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	if (queue->s.param.sched.lock_count >
	    SCHEDULE_ORDERED_LOCKS_PER_QUEUE)
		return -1;

	if (param->type == ODP_QUEUE_TYPE_SCHED)
		queue->s.param.deq_mode = ODP_QUEUE_OP_DISABLED;

	queue->s.type = queue->s.param.type;

	queue->s.enqueue = queue_enq;
	queue->s.dequeue = queue_deq;
	queue->s.enqueue_multi = queue_enq_multi;
	queue->s.dequeue_multi = queue_deq_multi;

	queue->s.pktin = PKTIN_INVALID;

	queue->s.head = NULL;
	queue->s.tail = NULL;

	queue->s.reorder_head = NULL;
	queue->s.reorder_tail = NULL;

	return 0;
}


int odp_queue_init_global(void)
{
	uint32_t i, j;
	odp_shm_t shm;

	ODP_DBG("Queue init ... ");

	shm = odp_shm_reserve("odp_queues",
			      sizeof(queue_table_t),
			      sizeof(queue_entry_t), 0);

	queue_tbl = odp_shm_addr(shm);

	if (queue_tbl == NULL)
		return -1;

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_qentry(i);
		LOCK_INIT(&queue->s.lock);
		for (j = 0; j < SCHEDULE_ORDERED_LOCKS_PER_QUEUE; j++) {
			odp_atomic_init_u64(&queue->s.sync_in[j], 0);
			odp_atomic_init_u64(&queue->s.sync_out[j], 0);
		}
		queue->s.index  = i;
		queue->s.handle = queue_from_id(i);
	}

	ODP_DBG("done\n");
	ODP_DBG("Queue init global\n");
	ODP_DBG("  struct queue_entry_s size %zu\n",
		sizeof(struct queue_entry_s));
	ODP_DBG("  queue_entry_t size        %zu\n",
		sizeof(queue_entry_t));
	ODP_DBG("\n");

	return 0;
}

int odp_queue_term_global(void)
{
	int ret = 0;
	int rc = 0;
	queue_entry_t *queue;
	int i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];
		LOCK(&queue->s.lock);
		if (queue->s.status != QUEUE_STATUS_FREE) {
			ODP_ERR("Not destroyed queue: %s\n", queue->s.name);
			rc = -1;
		}
		UNLOCK(&queue->s.lock);
	}

	ret = odp_shm_free(odp_shm_lookup("odp_queues"));
	if (ret < 0) {
		ODP_ERR("shm free failed for odp_queues");
		rc = -1;
	}

	return rc;
}

int odp_queue_capability(odp_queue_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = ODP_CONFIG_QUEUES - NUM_INTERNAL_QUEUES;
	capa->max_ordered_locks = SCHEDULE_ORDERED_LOCKS_PER_QUEUE;
	capa->max_sched_groups  = sched_fn->num_grps();
	capa->sched_prios       = odp_schedule_num_prio();

	return 0;
}

odp_queue_type_t odp_queue_type(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.type;
}

odp_schedule_sync_t odp_queue_sched_type(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync;
}

odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.prio;
}

odp_schedule_group_t odp_queue_sched_group(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.group;
}

int odp_queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		(int)queue->s.param.sched.lock_count : -1;
}

odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param)
{
	uint32_t i;
	queue_entry_t *queue;
	odp_queue_t handle = ODP_QUEUE_INVALID;
	odp_queue_type_t type = ODP_QUEUE_TYPE_PLAIN;
	odp_queue_param_t default_param;

	if (param == NULL) {
		odp_queue_param_init(&default_param);
		param = &default_param;
	}

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE) {
			continue;
		}

		LOCK(&queue->s.lock);
		if (queue->s.status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(&queue->s.lock);
				return handle;
			}

			type = queue->s.type;

			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->s.status = QUEUE_STATUS_NOTSCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;
			UNLOCK(&queue->s.lock);
			break;
		}
		UNLOCK(&queue->s.lock);
	}

	if (handle != ODP_QUEUE_INVALID && type == ODP_QUEUE_TYPE_SCHED) {
		if (sched_fn->init_queue(queue->s.index,
					 &queue->s.param.sched)) {
			queue->s.status = QUEUE_STATUS_FREE;
			ODP_ERR("schedule queue init failed\n");
			return ODP_QUEUE_INVALID;
		}
	}

	return handle;
}

void sched_cb_queue_destroy_finalize(uint32_t queue_index)
{
	queue_entry_t *queue = get_qentry(queue_index);

	LOCK(&queue->s.lock);

	if (queue->s.status == QUEUE_STATUS_DESTROYED) {
		queue->s.status = QUEUE_STATUS_FREE;
		sched_fn->destroy_queue(queue_index);
	}
	UNLOCK(&queue->s.lock);
}

int odp_queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	queue = queue_to_qentry(handle);

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	LOCK(&queue->s.lock);
	if (queue->s.status == QUEUE_STATUS_FREE) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" already free\n", queue->s.name);
		return -1;
	}
	if (queue->s.status == QUEUE_STATUS_DESTROYED) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" already destroyed\n", queue->s.name);
		return -1;
	}
	if (queue->s.head != NULL) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" not empty\n", queue->s.name);
		return -1;
	}
	if (queue_is_ordered(queue) && queue->s.reorder_head) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue \"%s\" reorder queue not empty\n",
			queue->s.name);
		return -1;
	}

	switch (queue->s.status) {
	case QUEUE_STATUS_READY:
		queue->s.status = QUEUE_STATUS_FREE;
		break;
	case QUEUE_STATUS_NOTSCHED:
		queue->s.status = QUEUE_STATUS_FREE;
		sched_fn->destroy_queue(queue->s.index);
		break;
	case QUEUE_STATUS_SCHED:
		/* Queue is still in scheduling */
		queue->s.status = QUEUE_STATUS_DESTROYED;
		break;
	default:
		ODP_ABORT("Unexpected queue status\n");
	}
	UNLOCK(&queue->s.lock);

	return 0;
}

int odp_queue_context_set(odp_queue_t handle, void *context,
			  uint32_t len ODP_UNUSED)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);
	odp_mb_full();
	queue->s.param.context = context;
	odp_mb_full();
	return 0;
}

void *odp_queue_context(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);
	return queue->s.param.context;
}

odp_queue_t odp_queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->s.status == QUEUE_STATUS_FREE ||
		    queue->s.status == QUEUE_STATUS_DESTROYED)
			continue;

		LOCK(&queue->s.lock);
		if (strcmp(name, queue->s.name) == 0) {
			/* found it */
			UNLOCK(&queue->s.lock);
			return queue->s.handle;
		}
		UNLOCK(&queue->s.lock);
	}

	return ODP_QUEUE_INVALID;
}

int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr, int sustain)
{
	int ret;

	if (sched_fn->ord_enq(queue->s.index, buf_hdr, sustain, &ret))
		return ret;

	LOCK(&queue->s.lock);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	queue_add(queue, buf_hdr);

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		UNLOCK(&queue->s.lock);
		if (sched_fn->sched_queue(queue->s.index))
			ODP_ABORT("schedule_queue failed\n");
		return 0;
	}

	UNLOCK(&queue->s.lock);
	return 0;
}

int queue_prepend(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	queue_entry_t *origin_qe;
	uint64_t order;

	get_queue_order(&origin_qe, &order, buf_hdr);
	if (origin_qe) {
		ODP_ERR("Prepend does not handle ordered queues!\n");
		return -1;
	}

	LOCK(&queue->s.lock);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	queue_pre(queue, buf_hdr);

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		UNLOCK(&queue->s.lock);
		if (sched_fn->sched_queue(queue->s.index))
			ODP_ABORT("schedule_queue failed\n");
		return 0;
	}
	UNLOCK(&queue->s.lock);
	return 0;
}

int queue_prepend_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], 
			int num)
{
	//XXX: This is very similar to queue_enq_multi, need to refactor at some
	// point
	int sched = 0;
	int i;
	queue_entry_t *origin_qe;
	uint64_t order;

	/* Chain input buffers together */
	for (i = 0; i < num - 1; i++)
		buf_hdr[i]->next = buf_hdr[i + 1];

	/* Handle ordered enqueues commonly via links */
	get_queue_order(&origin_qe, &order, buf_hdr[0]);
	if (origin_qe) {
		ODP_ERR("No ordered queue support in prepend!\n");
		return -1;
	}

	/* Handle unordered enqueues */
	LOCK(&queue->s.lock);
	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	/* Empty queue */
	if (queue->s.head == NULL) {
		queue->s.head = buf_hdr[0];
		queue->s.tail = buf_hdr[num - 1];
		buf_hdr[num - 1]->next = NULL;
	} else {
		buf_hdr[num - 1]->next = queue->s.head;
		queue->s.head = buf_hdr[0];
	}

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		sched = 1; /* retval: schedule queue */
	}
	UNLOCK(&queue->s.lock);

	/* Add queue to scheduling */
	if (sched && sched_fn->sched_queue(queue->s.index))
		ODP_ABORT("schedule_queue failed\n");

	return num; /* All events enqueued */
}

int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
		    int num, int sustain)
{
	int sched = 0;
	int i, ret;
	odp_buffer_hdr_t *tail;

	/* Chain input buffers together */
	for (i = 0; i < num - 1; i++)
		buf_hdr[i]->next = buf_hdr[i + 1];

	tail = buf_hdr[num - 1];
	buf_hdr[num - 1]->next = NULL;

	if (sched_fn->ord_enq_multi(queue->s.index, (void **)buf_hdr, num,
				    sustain, &ret))
		return ret;

	/* Handle unordered enqueues */
	LOCK(&queue->s.lock);
	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	/* Empty queue */
	if (queue->s.head == NULL)
		queue->s.head = buf_hdr[0];
	else
		queue->s.tail->next = buf_hdr[0];

	queue->s.tail = tail;

	if (queue->s.status == QUEUE_STATUS_NOTSCHED) {
		queue->s.status = QUEUE_STATUS_SCHED;
		sched = 1; /* retval: schedule queue */
	}
	UNLOCK(&queue->s.lock);

	/* Add queue to scheduling */
	if (sched && sched_fn->sched_queue(queue->s.index))
		ODP_ABORT("schedule_queue failed\n");

	return num; /* All events enqueued */
}

int odp_queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	for (i = 0; i < num; i++)
		buf_hdr[i] = odp_buf_to_hdr(odp_buffer_from_event(ev[i]));

	return num == 0 ? 0 : queue->s.enqueue_multi(queue, buf_hdr,
						     num, SUSTAIN_ORDER);
}

int odp_queue_enq(odp_queue_t handle, odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	queue   = queue_to_qentry(handle);
	buf_hdr = odp_buf_to_hdr(odp_buffer_from_event(ev));

	/* No chains via this entry */
	buf_hdr->link = NULL;

	return queue->s.enqueue(queue, buf_hdr, SUSTAIN_ORDER);
}

odp_buffer_hdr_t *queue_deq(queue_entry_t *queue)
{
	odp_buffer_hdr_t *buf_hdr;
	uint32_t i;

	LOCK(&queue->s.lock);

	if (queue->s.head == NULL) {
		/* Already empty queue */
		if (queue->s.status == QUEUE_STATUS_SCHED)
			queue->s.status = QUEUE_STATUS_NOTSCHED;

		UNLOCK(&queue->s.lock);
		return NULL;
	}

	buf_hdr       = queue->s.head;
	queue->s.head = buf_hdr->next;
	buf_hdr->next = NULL;

	/* Note that order should really be assigned on enq to an
	 * ordered queue rather than deq, however the logic is simpler
	 * to do it here and has the same effect.
	 */
	if (queue_is_ordered(queue)) {
		buf_hdr->origin_qe = queue;
		buf_hdr->order = queue->s.order_in++;
		for (i = 0; i < queue->s.param.sched.lock_count; i++) {
			buf_hdr->sync[i] =
				odp_atomic_fetch_inc_u64(&queue->s.sync_in[i]);
		}
		buf_hdr->flags.sustain = SUSTAIN_ORDER;
	} else {
		buf_hdr->origin_qe = NULL;
	}

	if (queue->s.head == NULL) {
		/* Queue is now empty */
		queue->s.tail = NULL;
	}
	UNLOCK(&queue->s.lock);

	return buf_hdr;
}


int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	odp_buffer_hdr_t *hdr;
	int i;
	uint32_t j;

	LOCK(&queue->s.lock);
	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed.
		 * Scheduler finalizes queue destroy after this. */
		UNLOCK(&queue->s.lock);
		return -1;
	}

	hdr = queue->s.head;

	if (hdr == NULL) {
		/* Already empty queue */
		if (queue->s.status == QUEUE_STATUS_SCHED)
			queue->s.status = QUEUE_STATUS_NOTSCHED;

		UNLOCK(&queue->s.lock);
		return 0;
	}

	for (i = 0; i < num && hdr; i++) {
		buf_hdr[i]       = hdr;
		hdr              = hdr->next;
		buf_hdr[i]->next = NULL;
		if (queue_is_ordered(queue)) {
			buf_hdr[i]->origin_qe = queue;
			buf_hdr[i]->order     = queue->s.order_in++;
			for (j = 0; j < queue->s.param.sched.lock_count; j++) {
				buf_hdr[i]->sync[j] =
					odp_atomic_fetch_inc_u64
					(&queue->s.sync_in[j]);
			}
			buf_hdr[i]->flags.sustain = SUSTAIN_ORDER;
		} else {
			buf_hdr[i]->origin_qe = NULL;
		}
	}

	queue->s.head = hdr;

	if (hdr == NULL) {
		/* Queue is now empty */
		queue->s.tail = NULL;
	}

	UNLOCK(&queue->s.lock);

	return i;
}


int odp_queue_deq_multi(odp_queue_t handle, odp_event_t events[], int num)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	int i, ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	ret = queue->s.dequeue_multi(queue, buf_hdr, num);

	for (i = 0; i < ret; i++)
		events[i] = odp_buffer_to_event(buf_hdr[i]->handle.handle);

	return ret;
}

odp_event_t odp_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr;

	queue   = queue_to_qentry(handle);
	buf_hdr = queue->s.dequeue(queue);

	if (buf_hdr)
		return odp_buffer_to_event(buf_hdr->handle.handle);

	return ODP_EVENT_INVALID;
}

int odp_queue_is_empty(odp_queue_t queue)
{
    queue_entry_t *q;
    q = queue_to_qentry(queue);

    if (q->s.head == NULL) {
        return 1;
    }
    return 0;
}

void queue_lock(queue_entry_t *queue)
{
	LOCK(&queue->s.lock);
}

void queue_unlock(queue_entry_t *queue)
{
	UNLOCK(&queue->s.lock);
}

void odp_queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	params->sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	params->sched.group = ODP_SCHED_GROUP_ALL;
}

int odp_queue_info(odp_queue_t handle, odp_queue_info_t *info)
{
	uint32_t queue_id;
	queue_entry_t *queue;
	int status;

	if (odp_unlikely(info == NULL)) {
		ODP_ERR("Unable to store info, NULL ptr given\n");
		return -1;
	}

	queue_id = queue_to_id(handle);

	if (odp_unlikely(queue_id >= ODP_CONFIG_QUEUES)) {
		ODP_ERR("Invalid queue handle:%" PRIu64 "\n",
			odp_queue_to_u64(handle));
		return -1;
	}

	queue = get_qentry(queue_id);

	LOCK(&queue->s.lock);
	status = queue->s.status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->s.name;
	info->param = queue->s.param;

	UNLOCK(&queue->s.lock);

	return 0;
}

int sched_cb_num_queues(void)
{
	return ODP_CONFIG_QUEUES;
}

int sched_cb_queue_prio(uint32_t queue_index)
{
	queue_entry_t *qe = get_qentry(queue_index);

	return qe->s.param.sched.prio;
}

int sched_cb_queue_grp(uint32_t queue_index)
{
	queue_entry_t *qe = get_qentry(queue_index);

	return qe->s.param.sched.group;
}

int sched_cb_queue_is_ordered(uint32_t queue_index)
{
	return queue_is_ordered(get_qentry(queue_index));
}

int sched_cb_queue_is_atomic(uint32_t queue_index)
{
	return queue_is_atomic(get_qentry(queue_index));
}

odp_queue_t sched_cb_queue_handle(uint32_t queue_index)
{
	return queue_from_id(queue_index);
}

int sched_cb_queue_deq_multi(uint32_t queue_index, odp_event_t ev[], int num)
{
	int i, ret;
	queue_entry_t *qe = get_qentry(queue_index);
	odp_buffer_hdr_t *buf_hdr[num];

	ret = queue_deq_multi(qe, buf_hdr, num);

	if (ret > 0)
		for (i = 0; i < ret; i++)
			ev[i] = odp_buffer_to_event(buf_hdr[i]->handle.handle);

	return ret;
}

int sched_cb_queue_empty(uint32_t queue_index)
{
	queue_entry_t *queue = get_qentry(queue_index);
	int ret = 0;

	LOCK(&queue->s.lock);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		UNLOCK(&queue->s.lock);
		return -1;
	}

	if (queue->s.head == NULL) {
		/* Already empty queue. Update status. */
		if (queue->s.status == QUEUE_STATUS_SCHED)
			queue->s.status = QUEUE_STATUS_NOTSCHED;

		ret = 1;
	}

	UNLOCK(&queue->s.lock);

	return ret;
}
