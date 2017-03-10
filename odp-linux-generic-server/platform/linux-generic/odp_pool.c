/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/chained_buffer.h>
#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp_internal.h>
#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <odp/api/thread.h>
#include <odp_debug_internal.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#if ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#error ODP_CONFIG_POOLS > ODP_BUFFER_MAX_POOLS
#endif

typedef union buffer_type_any_u {
	odp_buffer_hdr_t  buf;
	odp_packet_hdr_t  pkt;
	odp_timeout_hdr_t tmo;
} odp_anybuf_t;

/* Any buffer type header */
typedef struct {
	union buffer_type_any_u any_hdr;    /* any buffer type */
} odp_any_buffer_hdr_t;

typedef struct odp_any_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_any_buffer_hdr_t))];
} odp_any_hdr_stride;

typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_POOLS];
} pool_table_t;

/* The pool table */
static pool_table_t *pool_tbl;
static const char SHM_DEFAULT_NAME[] = "odp_buffer_pools";

/* Pool entry pointers (for inlining) */
void *pool_entry_ptr[ODP_CONFIG_POOLS];

/* Cache thread id locally for local cache performance */
static __thread int local_id;

int odp_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve(SHM_DEFAULT_NAME,
			      sizeof(pool_table_t),
			      sizeof(pool_entry_t), 0);

	pool_tbl = odp_shm_addr(shm);

	if (pool_tbl == NULL)
		return -1;

	memset(pool_tbl, 0, sizeof(pool_table_t));

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		/* init locks */
		pool_entry_t *pool = &pool_tbl->pool[i];
		POOL_LOCK_INIT(&pool->s.lock);
#ifndef POOL_USE_LOCKLESS
		POOL_LOCK_INIT(&pool->s.buf_lock);
		POOL_LOCK_INIT(&pool->s.blk_lock);
#endif
		pool->s.pool_hdl = pool_index_to_handle(i);
		pool->s.pool_id = i;
		pool_entry_ptr[i] = pool;
		odp_atomic_init_u32(&pool->s.bufcount, 0);
		odp_atomic_init_u32(&pool->s.blkcount, 0);

		/* Initialize pool statistics counters */
		odp_atomic_init_u64(&pool->s.poolstats.bufallocs, 0);
		odp_atomic_init_u64(&pool->s.poolstats.buffrees, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blkallocs, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blkfrees, 0);
		odp_atomic_init_u64(&pool->s.poolstats.bufempty, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blkempty, 0);
		odp_atomic_init_u64(&pool->s.poolstats.buf_high_wm_count, 0);
		odp_atomic_init_u64(&pool->s.poolstats.buf_low_wm_count, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blk_high_wm_count, 0);
		odp_atomic_init_u64(&pool->s.poolstats.blk_low_wm_count, 0);
	}

	ODP_DBG("\nPool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");
	return 0;
}

int odp_pool_init_local(void)
{
	local_id = odp_thread_id();
	return 0;
}

int odp_pool_term_global(void)
{
	int i;
	pool_entry_t *pool;
	int ret = 0;
	int rc = 0;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (pool->s.pool_shm != ODP_SHM_INVALID) {
			ODP_ERR("Not destroyed pool: %s\n", pool->s.name);
			rc = -1;
		}
		POOL_UNLOCK(&pool->s.lock);
	}

	ret = odp_shm_free(odp_shm_lookup(SHM_DEFAULT_NAME));
	if (ret < 0) {
		ODP_ERR("shm free failed for %s", SHM_DEFAULT_NAME);
		rc = -1;
	}

	return rc;
}

int odp_pool_term_local(void)
{
	_odp_flush_caches();
	return 0;
}

int odp_pool_capability(odp_pool_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pool_capability_t));

	capa->max_pools = ODP_CONFIG_POOLS;

	/* Buffer pools */
	capa->buf.max_pools = ODP_CONFIG_POOLS;
	capa->buf.max_align = ODP_CONFIG_BUFFER_ALIGN_MAX;
	capa->buf.max_size  = 0;
	capa->buf.max_num   = 0;

	/* Packet pools */
	capa->pkt.max_pools        = ODP_CONFIG_POOLS;
	capa->pkt.max_len          = ODP_CONFIG_PACKET_MAX_SEGS *
				     ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_num	   = 0;
	capa->pkt.min_headroom     = ODP_CONFIG_PACKET_HEADROOM;
	capa->pkt.min_tailroom     = ODP_CONFIG_PACKET_TAILROOM;
	capa->pkt.max_segs_per_pkt = ODP_CONFIG_PACKET_MAX_SEGS;
	capa->pkt.min_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_seg_len      = ODP_CONFIG_PACKET_SEG_LEN_MAX;
	capa->pkt.max_uarea_size   = 0;

	/* Timeout pools */
	capa->tmo.max_pools = ODP_CONFIG_POOLS;
	capa->tmo.max_num   = 0;

	return 0;
}

/**
 * Pool creation
 */

odp_pool_t _pool_create(const char *name,
			odp_pool_param_t *params,
			uint32_t shmflags)
{
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	pool_entry_t *pool;
	uint32_t i, headroom = 0, tailroom = 0;
	odp_shm_t shm;

	if (params == NULL)
		return ODP_POOL_INVALID;

	/* Default size and align for timeouts */
	if (params->type == ODP_POOL_TIMEOUT) {
		params->buf.size  = 0; /* tmo.__res1 */
		params->buf.align = 0; /* tmo.__res2 */
	}

	/* Default initialization parameters */
	uint32_t p_udata_size = 0;
	uint32_t udata_stride = 0;

	/* Restriction for v1.0: All non-packet buffers are unsegmented */
	int unseg = 1;

	/* Restriction for v1.0: No zeroization support */
	const int zeroized = 0;

	uint32_t blk_size, buf_stride, buf_num, blk_num, seg_len = 0;
	uint32_t buf_align =
		params->type == ODP_POOL_BUFFER ? params->buf.align : 0;

	/* Validate requested buffer alignment */
	if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
	    buf_align != ODP_ALIGN_ROUNDDOWN_POWER_2(buf_align, buf_align))
		return ODP_POOL_INVALID;

	/* Set correct alignment based on input request */
	if (buf_align == 0)
		buf_align = ODP_CACHE_LINE_SIZE;
	else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
		buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

	/* Calculate space needed for buffer blocks and metadata */
	switch (params->type) {
	case ODP_POOL_BUFFER:
	case ODP_POOL_SOCK_CONN:
	case ODP_POOL_FILE_IO_COMPL:
		unseg = 0; /* Buffers can be segmented to support large sizes */
		buf_num  = params->buf.num;
		blk_size = params->buf.size;
		seg_len = blk_size;

		/* Optimize small raw buffers */
		if (blk_size > ODP_MAX_INLINE_BUF || params->buf.align != 0)
			blk_size = ODP_ALIGN_ROUNDUP(blk_size, buf_align);

		buf_stride = sizeof(odp_buffer_hdr_stride);
		break;

	case ODP_POOL_PACKET:
		unseg = 0; /* Packets are always segmented */
		headroom = ODP_CONFIG_PACKET_HEADROOM;
		tailroom = ODP_CONFIG_PACKET_TAILROOM;

		buf_num = params->pkt.num;

		seg_len = params->pkt.seg_len <= ODP_CONFIG_PACKET_SEG_LEN_MIN ?
			ODP_CONFIG_PACKET_SEG_LEN_MIN :
			(params->pkt.seg_len <= ODP_CONFIG_PACKET_SEG_LEN_MAX ?
			 params->pkt.seg_len : ODP_CONFIG_PACKET_SEG_LEN_MAX);

		seg_len = ODP_ALIGN_ROUNDUP(
			headroom + seg_len + tailroom,
			ODP_CONFIG_BUFFER_ALIGN_MIN);

		blk_size = params->pkt.len <= seg_len ? seg_len :
			ODP_ALIGN_ROUNDUP(params->pkt.len, seg_len);

		/* Reject create if pkt.len needs too many segments */
		if (blk_size / seg_len > ODP_BUFFER_MAX_SEG) {
			ODP_ERR("ODP_BUFFER_MAX_SEG exceed %d(%d)\n",
				blk_size / seg_len, ODP_BUFFER_MAX_SEG);
			return ODP_POOL_INVALID;
		}

		p_udata_size = params->pkt.uarea_size;
		udata_stride = ODP_ALIGN_ROUNDUP(p_udata_size,
						 sizeof(uint64_t));

		buf_stride = sizeof(odp_packet_hdr_stride);
		break;

	case ODP_POOL_TIMEOUT:
		blk_size = 0;
		buf_num = params->tmo.num;
		buf_stride = sizeof(odp_timeout_hdr_stride);
		break;

	default:
		return ODP_POOL_INVALID;
	}

	/* Validate requested number of buffers against addressable limits */
	if (buf_num >
	    (ODP_BUFFER_MAX_BUFFERS / (buf_stride / ODP_CACHE_LINE_SIZE))) {
		ODP_ERR("buf_num %d > then expected %d\n",
			buf_num, ODP_BUFFER_MAX_BUFFERS /
			(buf_stride / ODP_CACHE_LINE_SIZE));
		return ODP_POOL_INVALID;
	}

	/* Find an unused buffer pool slot and iniitalize it as requested */
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (pool->s.pool_shm != ODP_SHM_INVALID) {
			POOL_UNLOCK(&pool->s.lock);
			continue;
		}

		/* found free pool */
		size_t block_size, pad_size, mdata_size, udata_size;

		pool->s.flags.all = 0;

		if (name == NULL) {
			pool->s.name[0] = 0;
		} else {
			strncpy(pool->s.name, name,
				ODP_POOL_NAME_LEN - 1);
			pool->s.name[ODP_POOL_NAME_LEN - 1] = 0;
			pool->s.flags.has_name = 1;
		}

		pool->s.params = *params;
		pool->s.buf_align = buf_align;

		/* Optimize for short buffers: Data stored in buffer hdr */
		if (blk_size <= ODP_MAX_INLINE_BUF) {
			block_size = 0;
			pool->s.buf_align = blk_size == 0 ? 0 : sizeof(void *);
		} else {
			block_size = buf_num * blk_size;
			pool->s.buf_align = buf_align;
		}

		pad_size = ODP_CACHE_LINE_SIZE_ROUNDUP(block_size) - block_size;
		mdata_size = buf_num * buf_stride;
		udata_size = buf_num * udata_stride;

		pool->s.buf_num   = buf_num;
		pool->s.pool_size = ODP_PAGE_SIZE_ROUNDUP(block_size +
							  pad_size +
							  mdata_size +
							  udata_size);

		shm = odp_shm_reserve(pool->s.name,
				      pool->s.pool_size,
				      ODP_PAGE_SIZE, shmflags);
		if (shm == ODP_SHM_INVALID) {
			POOL_UNLOCK(&pool->s.lock);
			return ODP_POOL_INVALID;
		}
		pool->s.pool_base_addr = odp_shm_addr(shm);
		pool->s.pool_shm = shm;

		/* Now safe to unlock since pool entry has been allocated */
		POOL_UNLOCK(&pool->s.lock);

		pool->s.flags.unsegmented = unseg;
		pool->s.flags.zeroized = zeroized;
		pool->s.seg_size = unseg ? blk_size : seg_len;
		pool->s.blk_size = blk_size;

		uint8_t *block_base_addr = pool->s.pool_base_addr;
		uint8_t *mdata_base_addr =
			block_base_addr + block_size + pad_size;
		uint8_t *udata_base_addr = mdata_base_addr + mdata_size;

		/* Pool mdata addr is used for indexing buffer metadata */
		pool->s.pool_mdata_addr = mdata_base_addr;
		pool->s.udata_size = p_udata_size;

		pool->s.buf_stride = buf_stride;
#ifdef POOL_USE_LOCKLESS
		_odp_atomic_tptr_init(&pool->s.buf_freelist, NULL);
		_odp_atomic_tptr_init(&pool->s.blk_freelist, NULL);
#else
		pool->s.buf_freelist = NULL;
		pool->s.blk_freelist = NULL;
#endif

		/* Initialization will increment these to their target vals */
		odp_atomic_store_u32(&pool->s.bufcount, 0);
		odp_atomic_store_u32(&pool->s.blkcount, 0);

		uint8_t *buf = udata_base_addr - buf_stride;
		uint8_t *udat = udata_stride == 0 ? NULL :
			udata_base_addr + udata_size - udata_stride;

		/* Init buffer common header and add to pool buffer freelist */
		do {
			odp_buffer_hdr_t *tmp =
				(odp_buffer_hdr_t *)(void *)buf;

			/* Iniitalize buffer metadata */
			tmp->allocator = ODP_FREEBUF;
			tmp->flags.all = 0;
			tmp->flags.zeroized = zeroized;
			tmp->size = 0;
			odp_atomic_init_u32(&tmp->ref_count, 0);
			tmp->type = params->type;
			tmp->event_type = params->type;
			tmp->pool_hdl = pool->s.pool_hdl;
			tmp->uarea_addr = (void *)udat;
			tmp->uarea_size = p_udata_size;
			tmp->segcount = 0;
			tmp->segsize = pool->s.seg_size;
			tmp->handle.handle = odp_buffer_encode_handle(tmp);
			/* Fields used to make a chained buffer if needed */
			tmp->next_segs = NULL;
			tmp->prev_segs = NULL;
			tmp->seg_list_pos = 0;
			tmp->num_segnodes  = 0;
			/**************************************************/

			/* Set 1st seg addr for zero-len buffers */
			tmp->addr[0] = NULL;

			/* Special case for short buffer data */
			if (blk_size <= ODP_MAX_INLINE_BUF) {
				tmp->flags.hdrdata = 1;
				if (blk_size > 0) {
					tmp->segcount = 1;
					tmp->addr[0] = &tmp->addr[1];
					tmp->size = blk_size;
				}
			}

			/* Push buffer onto pool's freelist */
			ret_buf(&pool->s, tmp);
			buf  -= buf_stride;
			udat -= udata_stride;
		} while (buf >= mdata_base_addr);

		/* Form block freelist for pool */
		uint8_t *blk =
			block_base_addr + block_size - pool->s.seg_size;

		if (blk_size > ODP_MAX_INLINE_BUF)
			do {
				ret_blk(&pool->s, blk);
				blk -= pool->s.seg_size;
			} while (blk >= block_base_addr);

		blk_num = odp_atomic_load_u32(&pool->s.blkcount);

		/* Initialize pool statistics counters */
		odp_atomic_store_u64(&pool->s.poolstats.bufallocs, 0);
		odp_atomic_store_u64(&pool->s.poolstats.buffrees, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blkallocs, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blkfrees, 0);
		odp_atomic_store_u64(&pool->s.poolstats.bufempty, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blkempty, 0);
		odp_atomic_store_u64(&pool->s.poolstats.buf_high_wm_count, 0);
		odp_atomic_store_u64(&pool->s.poolstats.buf_low_wm_count, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blk_high_wm_count, 0);
		odp_atomic_store_u64(&pool->s.poolstats.blk_low_wm_count, 0);

		/* Reset other pool globals to initial state */
		pool->s.buf_low_wm_assert = 0;
		pool->s.blk_low_wm_assert = 0;
		pool->s.quiesced = 0;
		pool->s.headroom = headroom;
		pool->s.tailroom = tailroom;

		/* Watermarks are hard-coded for now to control caching */
		pool->s.buf_high_wm = buf_num / 2;
		pool->s.buf_low_wm  = buf_num / 4;
		pool->s.blk_high_wm = blk_num / 2;
		pool->s.blk_low_wm = blk_num / 4;

		pool_hdl = pool->s.pool_hdl;
		break;
	}

	return pool_hdl;
}

odp_pool_t odp_pool_create(const char *name,
			   odp_pool_param_t *params)
{
#ifdef _ODP_PKTIO_IPC
	if (params && (params->type == ODP_POOL_PACKET))
		return _pool_create(name, params, ODP_SHM_PROC);
#endif
	return _pool_create(name, params, 0);

}

odp_pool_t odp_pool_lookup(const char *name)
{
	uint32_t i;
	pool_entry_t *pool;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = get_pool_entry(i);

		POOL_LOCK(&pool->s.lock);
		if (strcmp(name, pool->s.name) == 0) {
			/* found it */
			POOL_UNLOCK(&pool->s.lock);
			return pool->s.pool_hdl;
		}
		POOL_UNLOCK(&pool->s.lock);
	}

	return ODP_POOL_INVALID;
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);

	if (pool == NULL || info == NULL)
		return -1;

	info->name = pool->s.name;
	info->params = pool->s.params;

	return 0;
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	int i;

	if (pool == NULL)
		return -1;

	POOL_LOCK(&pool->s.lock);

	/* Call fails if pool is not allocated or predefined*/
	if (pool->s.pool_shm == ODP_SHM_INVALID ||
	    pool->s.flags.predefined) {
		POOL_UNLOCK(&pool->s.lock);
		ODP_ERR("invalid shm for pool %s\n", pool->s.name);
		return -1;
	}

	/* Make sure local caches are empty */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		flush_cache(&pool->s.local_cache[i], &pool->s);
		flush_blk_cache(&pool->s.local_blk_cache[i], &pool->s);
	}

	/* Call fails if pool has allocated buffers */
	if (odp_atomic_load_u32(&pool->s.bufcount) < pool->s.buf_num) {
		POOL_UNLOCK(&pool->s.lock);
		ODP_DBG("error: pool has allocated buffers %d/%d\n",
			odp_atomic_load_u32(&pool->s.bufcount),
			pool->s.buf_num);
		return -1;
	}

	odp_shm_free(pool->s.pool_shm);
	pool->s.pool_shm = ODP_SHM_INVALID;
	POOL_UNLOCK(&pool->s.lock);

	return 0;
}

inline void *get_blk(struct pool_entry_s *pool)
{
	void *myhead;
	uint64_t blkcount;

#ifdef POOL_USE_LOCKLESS
	_odp_atomic_tptr_t oldhead, newhead;

	oldhead = _odp_atomic_tptr_load(&pool->blk_freelist, _ODP_MEMMODEL_ACQ);

	do {
		if (odp_unlikely(odp_get_tptr(oldhead) == NULL))
			break;
		newhead = oldhead;
		odp_set_tptr(newhead, ((odp_buf_blk_t *)odp_get_tptr(oldhead))->next);
		odp_retag_tptr(newhead);
	} while (odp_cs_tptr(pool->blk_freelist, oldhead, newhead) == 0);
	myhead = (void*)odp_get_tptr(oldhead);
#else
	POOL_LOCK(&pool->blk_lock);

	myhead = pool->blk_freelist;

	if (odp_likely(myhead != NULL))
		pool->blk_freelist = ((odp_buf_blk_t *)myhead)->next;

	POOL_UNLOCK(&pool->blk_lock);
#endif

	if (odp_unlikely(myhead == NULL))
		odp_atomic_inc_u64(&pool->poolstats.blkempty);
	else {
		blkcount = odp_atomic_fetch_sub_u32(&pool->blkcount, 1) - 1;
		if (blkcount == pool->blk_low_wm && !pool->blk_low_wm_assert) {
			pool->blk_low_wm_assert = 1;
			odp_atomic_inc_u64(&pool->poolstats.blk_low_wm_count);
		}
		odp_atomic_inc_u64(&pool->poolstats.blkallocs);
	}

	return myhead;
}

inline void ret_blk(struct pool_entry_s *pool, void *block)
{
	uint64_t blkcount;
#ifdef POOL_USE_LOCKLESS
	_odp_atomic_tptr_t oldhead, myblock;

	oldhead = _odp_atomic_tptr_load(&pool->blk_freelist, _ODP_MEMMODEL_ACQ);

	do {
		myblock = oldhead;
		((odp_buf_blk_t *)block)->next = odp_get_tptr(oldhead);
		odp_set_tptr(myblock, block);
		odp_retag_tptr(myblock);
	} while (odp_cs_tptr(pool->blk_freelist, oldhead, myblock) == 0);
#else
	POOL_LOCK(&pool->blk_lock);

	((odp_buf_blk_t *)block)->next = pool->blk_freelist;
	pool->blk_freelist = block;

	POOL_UNLOCK(&pool->blk_lock);
#endif

	blkcount = odp_atomic_fetch_add_u32(&pool->blkcount, 1);

	if (blkcount == pool->blk_high_wm && pool->blk_low_wm_assert) {
		pool->blk_low_wm_assert = 0;
		odp_atomic_inc_u64(&pool->poolstats.blk_high_wm_count);
	}
	odp_atomic_inc_u64(&pool->poolstats.blkfrees);
}

inline odp_buffer_hdr_t *get_buf(struct pool_entry_s *pool)
{
	odp_buffer_hdr_t *myhead;
#ifdef POOL_USE_LOCKLESS
	_odp_atomic_tptr_t oldhead, newhead;

	oldhead = _odp_atomic_tptr_load(&pool->buf_freelist, _ODP_MEMMODEL_ACQ);

	do {
		newhead = oldhead;
		if (odp_unlikely(odp_get_tptr(oldhead) == NULL))
			break;
		odp_set_tptr(newhead, ((odp_buffer_hdr_t *)odp_get_tptr(oldhead))->next);
		odp_retag_tptr(newhead);
	} while (odp_cs_tptr(pool->buf_freelist, oldhead, newhead) == 0);

	myhead = (odp_buffer_hdr_t*)odp_get_tptr(oldhead);
#else
	POOL_LOCK(&pool->buf_lock);

	myhead = pool->buf_freelist;

	if (odp_likely(myhead != NULL))
		pool->buf_freelist = myhead->next;
	POOL_UNLOCK(&pool->buf_lock);
#endif

	if (odp_unlikely(myhead == NULL)) {
		odp_atomic_inc_u64(&pool->poolstats.bufempty);
	} else {
		uint64_t bufcount =
			odp_atomic_fetch_sub_u32(&pool->bufcount, 1) - 1;

		/* Check for low watermark condition */
		if (bufcount <= pool->buf_low_wm && !pool->buf_low_wm_assert) {
			pool->buf_low_wm_assert = 1;
			odp_atomic_inc_u64(&pool->poolstats.buf_low_wm_count);
		}

		odp_atomic_inc_u64(&pool->poolstats.bufallocs);
		ODP_ASSERT(myhead->allocator == ODP_FREEBUF);
		myhead->allocator = odp_thread_id();
	}

	return (void *)myhead;
}

inline void ret_buf(struct pool_entry_s *pool, odp_buffer_hdr_t *buf)
{
	buf->allocator = ODP_FREEBUF;  /* Mark buffer free */
	/* Reset the chained buffer parts */
	buf->next_segs = NULL;
	buf->prev_segs = NULL;
	buf->seg_list_pos = 0;
	buf->num_segnodes = 0;

	if (!buf->flags.hdrdata && buf->type != ODP_EVENT_BUFFER) {
		while (buf->segcount > 0) {
			if (buffer_is_secure(buf) || pool_is_secure(pool))
				memset(buf->addr[buf->segcount - 1],
				       0, buf->segsize);
			ret_blk(pool, buf->addr[--buf->segcount]);
			buf->addr[buf->segcount] = NULL;
		}
		buf->size = 0;
	}

#ifdef POOL_USE_LOCKLESS
	_odp_atomic_tptr_t oldhead, newhead;
	oldhead = _odp_atomic_tptr_load(&pool->buf_freelist, _ODP_MEMMODEL_ACQ);

	do {
		newhead = oldhead;
		buf->next = odp_get_tptr(oldhead);
		odp_set_tptr(newhead, buf);
		odp_retag_tptr(newhead);
	} while (odp_cs_tptr(pool->buf_freelist, oldhead, newhead) == 0);
#else
	POOL_LOCK(&pool->buf_lock);
	buf->next = pool->buf_freelist;
	pool->buf_freelist = buf;
	POOL_UNLOCK(&pool->buf_lock);
#endif
	uint64_t bufcount = odp_atomic_fetch_add_u32(&pool->bufcount, 1) + 1;

	/* Check if low watermark condition should be deasserted */
	if (bufcount == pool->buf_high_wm && pool->buf_low_wm_assert) {
		pool->buf_low_wm_assert = 0;
		odp_atomic_inc_u64(&pool->poolstats.buf_high_wm_count);
	}

	odp_atomic_inc_u64(&pool->poolstats.buffrees);
}

inline void *get_local_buf(local_cache_t *buf_cache,
			   struct pool_entry_s *pool,
			   size_t totsize)
{
	//uint32_t pool_id = pool_handle_to_index(pool->pool_hdl);
	/* Calculate the total number of blocks needed in case
	 * we allocate a local buffer with excess blks
	 */
	uint32_t total_blks_needed = 1;
	odp_buffer_hdr_t *buf = buf_cache->buf_freelist;

	if (odp_likely(buf != NULL)) {
		if ((buf->segcount * pool->seg_size) >= totsize) {
			total_blks_needed = (totsize % pool->seg_size) ?
				totsize / pool->seg_size + 1 : totsize / pool->seg_size;
		}
		buf_cache->buf_freelist = buf->next;

		if ((buf->segcount * pool->seg_size)  < totsize) {
			intmax_t needed = totsize - (buf->segcount * pool->seg_size);

			/* Get blocks from the local cache first */
			while (needed > 0) {
				void *blk = get_local_blk(
						&pool->local_blk_cache[local_id]);

				if (blk == NULL) {
					break;
				}
				buf->addr[buf->segcount++] = blk;
				assert(buf->segcount <= ODP_BUFFER_MAX_SEG);
				needed -= pool->seg_size;
			}

			/* If we exhaust the local cache, get blocks from global
			 * freelist
			 */
			while (needed > 0) {
				void *blk = get_blk(pool);
				if (odp_unlikely(blk == NULL)) {
					ret_buf(pool, buf);
					buf_cache->buffrees--;
					return NULL;
				}
				buf->addr[buf->segcount++] = blk;
				assert(buf->segcount <= ODP_BUFFER_MAX_SEG);
				needed -= pool->seg_size;
			}

			buf->size = buf->segcount * pool->seg_size;
		} else if (total_blks_needed < buf->segcount) {
			/* If the returned buffer is larger than needed, shed
			 * some blks to the local cache if we can
			 */
			while (total_blks_needed < buf->segcount) {
				/* Return blks to local cache */
				if (!pool->blk_low_wm_assert) {
					ret_local_blk(&pool->local_blk_cache[local_id], 
						      buf->addr[--buf->segcount]);
				} else {
					ret_blk(pool,
						buf->addr[--buf->segcount]);
				}
				buf->addr[buf->segcount] = NULL; /* Set segments
								    to NULL */
			}
			buf->size = buf->segcount * pool->seg_size;
		}

		buf_cache->bufallocs++;
		buf->size = buf->segcount * pool->seg_size;
		ODP_ASSERT(buf->allocator == ODP_FREEBUF);
		buf->allocator = odp_thread_id();  /* Mark buffer allocated */
	}

	return buf;
}

inline void *get_local_blk(local_blk_cache_t *blk_cache)
{
	odp_buf_blk_t *blk = blk_cache->blk_freelist;

	if (odp_likely(blk != NULL)) {
		blk_cache->blk_freelist = blk->next;
		blk_cache->blkallocs++;
	}
	return blk;
}

inline void ret_local_buf(local_cache_t *buf_cache,
			  odp_buffer_hdr_t *buf)
{
        /* Reset the chained buffer parts */
	buf->next_segs = NULL;
	buf->prev_segs = NULL;
	buf->seg_list_pos = 0;
	buf->num_segnodes = 0;
	/**********************************/
	buf->allocator = ODP_FREEBUF;
	buf->next = buf_cache->buf_freelist;
	buf_cache->buf_freelist = buf;

	buf_cache->buffrees++;
}

inline void ret_local_blk(local_blk_cache_t *blk_cache,
			odp_buf_blk_t* blk)
{
	blk->next = blk_cache->blk_freelist;
	blk_cache->blk_freelist = blk;
	blk_cache->blkfrees++;
}

int seg_alloc_head(odp_buffer_hdr_t *buf_hdr,  int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	void *newsegs[segcount];
	int i;

	for (i = 0; i < segcount; i++) {
		newsegs[i] = get_blk(&pool->s);
		if (newsegs[i] == NULL) {
			while (--i >= 0)
				ret_blk(&pool->s, newsegs[i]);
			return -1;
		}
	}

	for (i = buf_hdr->segcount - 1; i >= 0; i--)
		buf_hdr->addr[i + segcount] = buf_hdr->addr[i];

	for (i = 0; i < segcount; i++)
		buf_hdr->addr[i] = newsegs[i];

	buf_hdr->segcount += segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
	return 0;
}

void seg_free_head(odp_buffer_hdr_t *buf_hdr, int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	int s_cnt = buf_hdr->segcount;
	int i;

	for (i = 0; i < segcount; i++)
		ret_blk(&pool->s, buf_hdr->addr[i]);

	for (i = 0; i < s_cnt - segcount; i++)
		buf_hdr->addr[i] = buf_hdr->addr[i + segcount];

	buf_hdr->segcount -= segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
}

int seg_alloc_tail(odp_buffer_hdr_t *buf_hdr,  int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	uint32_t s_cnt = buf_hdr->segcount;
	int i;

	for (i = 0; i < segcount; i++) {
		buf_hdr->addr[s_cnt + i] = get_blk(&pool->s);
		if (buf_hdr->addr[s_cnt + i] == NULL) {
			while (--i >= 0)
				ret_blk(&pool->s, buf_hdr->addr[s_cnt + i]);
			return -1;
		}
	}

	buf_hdr->segcount += segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
	return 0;
}

void seg_free_tail(odp_buffer_hdr_t *buf_hdr, int segcount)
{
	uint32_t pool_id = pool_handle_to_index(buf_hdr->pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	int s_cnt = buf_hdr->segcount;
	int i;

	for (i = s_cnt - 1; i >= s_cnt - segcount; i--)
		ret_blk(&pool->s, buf_hdr->addr[i]);

	buf_hdr->segcount -= segcount;
	buf_hdr->size      = buf_hdr->segcount * pool->s.seg_size;
}

odp_buffer_t buffer_alloc(odp_pool_t pool_hdl, size_t size)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	uintmax_t totsize = pool->s.headroom + size + pool->s.tailroom;
	odp_anybuf_t *buf;
	assert(totsize >= size); /* No headroom/tailroom for this alloc */

	/* Reject oversized allocation requests */
	if ((pool->s.flags.unsegmented && totsize > pool->s.seg_size) ||
            (!pool->s.flags.unsegmented &&
	        totsize > pool->s.seg_size * ODP_BUFFER_MAX_SEG)) {
		return ODP_BUFFER_INVALID;
	}

	/* Try to satisfy request from the local cache */
	buf = (odp_anybuf_t *)
		(void *)get_local_buf(&pool->s.local_cache[local_id],
				      &pool->s, totsize);

	/* If cache is empty, satisfy request from the pool */
	if (odp_unlikely(buf == NULL)) {
		buf = (odp_anybuf_t *)(void *)get_buf(&pool->s);

		if (odp_unlikely(buf == NULL))
			return ODP_BUFFER_INVALID;

		/* Get blocks for this buffer, if pool uses application data */
		if ((buf->buf.segcount * pool->s.seg_size) < totsize) {
			intmax_t needed = totsize - (buf->buf.segcount *
						     pool->s.seg_size);
			/* Get blocks from the local cache first */
			while (needed > 0) {
				uint8_t *blk = get_local_blk(&pool->s.local_blk_cache[local_id]);
				if (blk == NULL) {
					break;
				}
				buf->buf.addr[buf->buf.segcount++] = blk;
				assert(buf->buf.segcount <= ODP_BUFFER_MAX_SEG);
				needed -= pool->s.seg_size;
			}

			/* Get any remaining blocks from the global freelist */
			while (needed > 0) {
				uint8_t *blk = get_blk(&pool->s);
				if (blk == NULL) {
					ret_buf(&pool->s, &buf->buf);
					return ODP_BUFFER_INVALID;
				}
				buf->buf.addr[buf->buf.segcount++] = blk;
				assert(buf->buf.segcount <= ODP_BUFFER_MAX_SEG);
				needed -= pool->s.seg_size;
			}
			buf->buf.size = buf->buf.segcount * pool->s.seg_size;
		}
	}
	buf->buf.size = buf->buf.segcount * pool->s.seg_size;

	/* Mark buffer as allocated */
	buf->buf.allocator = local_id;

	/* By default, buffers inherit their pool's zeroization setting */
	buf->buf.flags.zeroized = pool->s.flags.zeroized;

	/* By default, buffers are not associated with an ordered queue */
	buf->buf.origin_qe = NULL;
	buf->buf.next = NULL;

	return odp_hdr_to_buf(&buf->buf);
}

odp_buffer_t odp_buffer_alloc_size(odp_pool_t pool_hdl, size_t size)
{
    uint32_t pool_id = pool_handle_to_index(pool_hdl);
    pool_entry_t *pool = get_pool_entry(pool_id);
    uintmax_t totsize = pool->s.headroom + size + pool->s.tailroom;
    odp_buffer_t buf = ODP_BUFFER_INVALID;

    if (totsize > pool->s.seg_size * ODP_BUFFER_MAX_SEG) {
        buf = odp_chained_buffer_alloc(pool_hdl, size);
    } else {
        buf = buffer_alloc(pool_hdl, size);
    }

    return buf;
}

int buffer_alloc_multi(odp_pool_t pool_hdl, size_t size,
		       odp_buffer_t buf[], int num)
{
	int count;

	for (count = 0; count < num; ++count) {
		buf[count] = odp_buffer_alloc_size(pool_hdl, size);
		if (buf[count] == ODP_BUFFER_INVALID)
			break;
	}

	return count;
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	return buffer_alloc(pool_hdl,
			    odp_pool_to_entry(pool_hdl)->s.params.buf.size);
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num)
{
	size_t buf_size = odp_pool_to_entry(pool_hdl)->s.params.buf.size;

	return buffer_alloc_multi(pool_hdl, buf_size, buf, num);
}

void _buffer_free(odp_buffer_t buf)
{
	ODP_ASSERT(buf != ODP_BUFFER_INVALID);
	odp_buffer_hdr_t *buf_hdr = odp_buf_to_hdr(buf);
	pool_entry_t *pool = odp_buf_to_pool(buf_hdr);

	ODP_ASSERT(buf_hdr->allocator != ODP_FREEBUF);

	if (odp_unlikely(pool->s.buf_low_wm_assert || pool->s.blk_low_wm_assert))
		ret_buf(&pool->s, buf_hdr);
	else
		ret_local_buf(&pool->s.local_cache[local_id], buf_hdr);
}

void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	int i;

	for (i = 0; i < num; ++i)
		odp_buffer_free(buf[i]);
}

void odp_buffer_free(odp_buffer_t buf)
{
	ODP_ASSERT(buf != ODP_BUFFER_INVALID);
	odp_buffer_hdr_t *buf_hdr = odp_buf_to_hdr(buf);
	pool_entry_t *pool = odp_buf_to_pool(buf_hdr);

	ODP_ASSERT(buf_hdr->allocator != ODP_FREEBUF);

	if (odp_is_chained_buffer(buf)) {
		odp_chained_buffer_free(buf);
	} else {
		if (odp_unlikely(pool->s.buf_low_wm_assert))
			ret_buf(&pool->s, buf_hdr);
		else
			ret_local_buf(&pool->s.local_cache[local_id], buf_hdr);
	}
}

void _odp_flush_caches(void)
{
	int i;
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_entry_t *pool = get_pool_entry(i);
		flush_cache(&pool->s.local_cache[local_id], &pool->s);
		flush_blk_cache(&pool->s.local_blk_cache[local_id], &pool->s);
	}
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	pool_entry_t *pool;
	uint32_t pool_id;

	pool_id = pool_handle_to_index(pool_hdl);
	pool    = get_pool_entry(pool_id);

	uint32_t bufcount  = odp_atomic_load_u32(&pool->s.bufcount);
	uint32_t blkcount  = odp_atomic_load_u32(&pool->s.blkcount);
	uint64_t bufallocs = odp_atomic_load_u64(&pool->s.poolstats.bufallocs);
	uint64_t buffrees  = odp_atomic_load_u64(&pool->s.poolstats.buffrees);
	uint64_t blkallocs = odp_atomic_load_u64(&pool->s.poolstats.blkallocs);
	uint64_t blkfrees  = odp_atomic_load_u64(&pool->s.poolstats.blkfrees);
	uint64_t bufempty  = odp_atomic_load_u64(&pool->s.poolstats.bufempty);
	uint64_t blkempty  = odp_atomic_load_u64(&pool->s.poolstats.blkempty);
	uint64_t bufhiwmct =
		odp_atomic_load_u64(&pool->s.poolstats.buf_high_wm_count);
	uint64_t buflowmct =
		odp_atomic_load_u64(&pool->s.poolstats.buf_low_wm_count);
	uint64_t blkhiwmct =
		odp_atomic_load_u64(&pool->s.poolstats.blk_high_wm_count);
	uint64_t blklowmct =
		odp_atomic_load_u64(&pool->s.poolstats.blk_low_wm_count);

	ODP_DBG("Pool info\n");
	ODP_DBG("---------\n");
	ODP_DBG(" pool            %" PRIu64 "\n",
		odp_pool_to_u64(pool->s.pool_hdl));
	ODP_DBG(" name            %s\n",
		pool->s.flags.has_name ? pool->s.name : "Unnamed Pool");
	ODP_DBG(" pool type       %s\n",
		pool->s.params.type == ODP_POOL_BUFFER ? "buffer" :
	       (pool->s.params.type == ODP_POOL_PACKET ? "packet" :
	       (pool->s.params.type == ODP_POOL_TIMEOUT ? "timeout" :
		"unknown")));
	ODP_DBG(" pool storage    ODP managed shm handle %" PRIu64 "\n",
		odp_shm_to_u64(pool->s.pool_shm));
	ODP_DBG(" pool status     %s\n",
		pool->s.quiesced ? "quiesced" : "active");
	ODP_DBG(" pool opts       %s, %s, %s\n",
		pool->s.flags.unsegmented ? "unsegmented" : "segmented",
		pool->s.flags.zeroized ? "zeroized" : "non-zeroized",
		pool->s.flags.predefined  ? "predefined" : "created");
	ODP_DBG(" pool base       %p\n",  pool->s.pool_base_addr);
	ODP_DBG(" pool size       %zu (%zu pages)\n",
		pool->s.pool_size, pool->s.pool_size / ODP_PAGE_SIZE);
	ODP_DBG(" pool mdata base %p\n",  pool->s.pool_mdata_addr);
	ODP_DBG(" udata size      %zu\n", pool->s.udata_size);
	ODP_DBG(" headroom        %u\n",  pool->s.headroom);
	ODP_DBG(" tailroom        %u\n",  pool->s.tailroom);
	if (pool->s.params.type == ODP_POOL_BUFFER) {
		ODP_DBG(" buf size        %zu\n", pool->s.params.buf.size);
		ODP_DBG(" buf align       %u requested, %u used\n",
			pool->s.params.buf.align, pool->s.buf_align);
	} else if (pool->s.params.type == ODP_POOL_PACKET) {
		ODP_DBG(" seg length      %u requested, %u used\n",
			pool->s.params.pkt.seg_len, pool->s.seg_size);
		ODP_DBG(" pkt length      %u requested, %u used\n",
			pool->s.params.pkt.len, pool->s.blk_size);
	}
	ODP_DBG(" num bufs        %u\n",  pool->s.buf_num);
	ODP_DBG(" bufs available  %u %s\n", bufcount,
		pool->s.buf_low_wm_assert ? " **buf low wm asserted**" : "");
	ODP_DBG(" bufs in use     %u\n",  pool->s.buf_num - bufcount);
	ODP_DBG(" buf allocs      %lu\n", bufallocs);
	ODP_DBG(" buf frees       %lu\n", buffrees);
	ODP_DBG(" buf empty       %lu\n", bufempty);
	ODP_DBG(" blk size        %zu\n",
		pool->s.seg_size > ODP_MAX_INLINE_BUF ? pool->s.seg_size : 0);
	ODP_DBG(" blks available  %u %s\n",  blkcount,
		pool->s.blk_low_wm_assert ? " **blk low wm asserted**" : "");
	ODP_DBG(" blk allocs      %lu\n", blkallocs);
	ODP_DBG(" blk frees       %lu\n", blkfrees);
	ODP_DBG(" blk empty       %lu\n", blkempty);
	ODP_DBG(" buf high wm value   %lu\n", pool->s.buf_high_wm);
	ODP_DBG(" buf high wm count   %lu\n", bufhiwmct);
	ODP_DBG(" buf low wm value    %lu\n", pool->s.buf_low_wm);
	ODP_DBG(" buf low wm count    %lu\n", buflowmct);
	ODP_DBG(" blk high wm value   %lu\n", pool->s.blk_high_wm);
	ODP_DBG(" blk high wm count   %lu\n", blkhiwmct);
	ODP_DBG(" blk low wm value    %lu\n", pool->s.blk_low_wm);
	ODP_DBG(" blk low wm count    %lu\n", blklowmct);
}


odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	return odp_buf_to_hdr(buf)->pool_hdl;
}

void odp_pool_param_init(odp_pool_param_t *params)
{
	memset(params, 0, sizeof(odp_pool_param_t));
}
