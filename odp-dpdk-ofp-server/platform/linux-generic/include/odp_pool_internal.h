/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP buffer pool - internal header
 */

#ifndef ODP_POOL_INTERNAL_H_
#define ODP_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp/api/hints.h>
#include <odp_config_internal.h>
#include <odp/api/debug.h>
#include <odp/api/shared_memory.h>
#include <odp/api/atomic.h>
#include <odp/api/thread.h>
#include <string.h>

#include <odp_align_internal.h>
#include <odp_atomic_internal.h>
#include <odp_buffer_internal.h>

/**
 * Buffer initialization routine prototype
 *
 * @note Routines of this type MAY be passed as part of the
 * _odp_buffer_pool_init_t structure to be called whenever a
 * buffer is allocated to initialize the user metadata
 * associated with that buffer.
 */
typedef void (_odp_buf_init_t)(odp_buffer_t buf, void *buf_init_arg);

/**
 * Buffer pool initialization parameters
 * Used to communicate buffer pool initialization options. Internal for now.
 */
typedef struct _odp_buffer_pool_init_t {
	size_t udata_size;         /**< Size of user metadata for each buffer */
	_odp_buf_init_t *buf_init; /**< Buffer initialization routine to use */
	void *buf_init_arg;        /**< Argument to be passed to buf_init() */
} _odp_buffer_pool_init_t;         /**< Type of buffer initialization struct */

/* Local cache for buffer alloc/free acceleration */
typedef struct local_cache_t {
	union {
		struct {
			odp_buffer_hdr_t *buf_freelist;  /* The local cache */
			uint64_t bufallocs;  /* Local buffer alloc count */
			uint64_t buffrees;   /* Local buffer free count */
		};
		uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(uint64_t))];
	};
} local_cache_t;

/* Local cache for blk alloc/free acceleration and to reduce
 * fragmentation in the more generic server environment 
 */
typedef struct local_blk_cache_t {
	union {
		struct {
			odp_buf_blk_t *blk_freelist; /* The local blk cache */
			uint64_t blkallocs;	     /* Local blk alloc count */
			uint64_t blkfrees;	     /* Local blk free count */
		};
		uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(uint64_t))];
	};
} local_blk_cache_t;

/* Use ticketlock instead of spinlock */
#define POOL_USE_TICKETLOCK
//#define POOL_USE_PTHREADLOCK
//#define POOL_USE_LOCKLESS

#ifdef POOL_USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#define POOL_LOCK(a)      odp_ticketlock_lock(a)
#define POOL_UNLOCK(a)    odp_ticketlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_ticketlock_init(a)
#elif defined(POOL_USE_PTHREADLOCK)
#include <odp/pthreadlock.h>
#define POOL_LOCK(a)      odp_pthreadlock_lock(a)
#define POOL_UNLOCK(a)    odp_pthreadlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_pthreadlock_init(a)
#else
#include <odp/api/spinlock.h>
#define POOL_LOCK(a)      odp_spinlock_lock(a)
#define POOL_UNLOCK(a)    odp_spinlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_spinlock_init(a)
#endif

/**
 * ODP Pool stats - Maintain some useful stats regarding pool utilization
 */
typedef struct {
	odp_atomic_u64_t bufallocs;     /**< Count of successful buf allocs */
	odp_atomic_u64_t buffrees;      /**< Count of successful buf frees */
	odp_atomic_u64_t blkallocs;     /**< Count of successful blk allocs */
	odp_atomic_u64_t blkfrees;      /**< Count of successful blk frees */
	odp_atomic_u64_t bufempty;      /**< Count of unsuccessful buf allocs */
	odp_atomic_u64_t blkempty;      /**< Count of unsuccessful blk allocs */
	odp_atomic_u64_t buf_high_wm_count; /**< Count of high buf wm conditions */
	odp_atomic_u64_t buf_low_wm_count;  /**< Count of low buf wm conditions */
	odp_atomic_u64_t blk_high_wm_count;  /**< Count of high blk wm conditions */
	odp_atomic_u64_t blk_low_wm_count;   /**< Count of low blk wm conditions */
} _odp_pool_stats_t;

struct pool_entry_s {
#if defined (POOL_USE_TICKETLOCK)
	odp_ticketlock_t        lock ODP_ALIGNED_CACHE;
#elif defined(POOL_USE_PTHREADLOCK)
	odp_pthreadlock_t       lock ODP_ALIGNED_CACHE;
#elif defined(POOL_USE_SPINLOCK)
	odp_spinlock_t		lock ODP_ALIGNED_CACHE;
#endif

#if defined (POOL_USE_TICKETLOCK) && !defined(POOL_USE_LOCKLESS)
	odp_ticketlock_t        buf_lock;
	odp_ticketlock_t        blk_lock;
#elif defined (POOL_USE_PTHREADLOCK) && !defined(POOL_USE_LOCKLESS)
	odp_pthreadlock_t	buf_lock;
	odp_pthreadlock_t	blk_lock;
#elif defined (POOL_USE_SPINLOCK) && !defined(POOL_USE_SPINLOCK)
	odp_spinlock_t          buf_lock;
	odp_spinlock_t          blk_lock;
#endif

	char                    name[ODP_POOL_NAME_LEN];
	odp_pool_param_t        params;
	uint32_t                udata_size;
	odp_pool_t              pool_hdl;
	uint32_t                pool_id;
	odp_shm_t               pool_shm;
	union {
		uint32_t all;
		struct {
			uint32_t has_name:1;
			uint32_t user_supplied_shm:1;
			uint32_t unsegmented:1;
			uint32_t zeroized:1;
			uint32_t predefined:1;
		};
	} flags;
	uint32_t                quiesced;
	uint32_t                buf_low_wm_assert;
	uint32_t                blk_low_wm_assert;
	uint8_t                *pool_base_addr;
	uint8_t                *pool_mdata_addr;
	size_t                  pool_size;
	uint32_t                buf_align;
	uint32_t                buf_stride;
#ifdef POOL_USE_LOCKLESS
	_odp_atomic_tptr_t      buf_freelist;
	_odp_atomic_tptr_t      blk_freelist;
#else
	odp_buffer_hdr_t       *buf_freelist;
	void                   *blk_freelist;
#endif
	odp_atomic_u32_t        bufcount;
	odp_atomic_u32_t        blkcount;
	_odp_pool_stats_t       poolstats;
	uint32_t                buf_num;
	uint32_t                seg_size;
	uint32_t                blk_size;
	uint32_t                buf_high_wm;
	uint32_t                buf_low_wm;
	uint32_t                blk_high_wm;
	uint32_t                blk_low_wm;
	uint32_t                headroom;
	uint32_t                tailroom;

	local_cache_t local_cache[ODP_THREAD_COUNT_MAX] ODP_ALIGNED_CACHE;
	local_blk_cache_t local_blk_cache[ODP_THREAD_COUNT_MAX] ODP_ALIGNED_CACHE;
};

typedef union pool_entry_u {
	struct pool_entry_s s;

	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pool_entry_s))];
} pool_entry_t;

extern void *pool_entry_ptr[];

/* Forward declarations */
void *get_blk(struct pool_entry_s *pool);
void *get_local_blk(local_blk_cache_t *blk_cache);
void ret_blk(struct pool_entry_s *pool, void *block);
void ret_buf(struct pool_entry_s *pool, odp_buffer_hdr_t *buf);
odp_buffer_hdr_t *get_buf(struct pool_entry_s *pool);
void *get_local_buf(local_cache_t *buf_cache,
		struct pool_entry_s *pool,
		size_t totsize);
void ret_local_buf(local_cache_t *buf_cache, odp_buffer_hdr_t *buf);
void ret_local_blk(local_blk_cache_t *blk_cache, odp_buf_blk_t* blk);

#if defined(ODP_CONFIG_SECURE_POOLS) && (ODP_CONFIG_SECURE_POOLS == 1)
#define buffer_is_secure(buf) (buf->flags.zeroized)
#define pool_is_secure(pool) (pool->flags.zeroized)
#else
#define buffer_is_secure(buf) 0
#define pool_is_secure(pool) 0
#endif

#define odp_retag_tptr(ptr) \
	_odp_atomic_tptr_settag(&ptr, _odp_atomic_tptr_gettag(&ptr) + 1)

#define odp_get_tptr(ptr) \
	_odp_atomic_tptr_getptr(&ptr)

#define odp_set_tptr(ptr, newptr) \
	_odp_atomic_tptr_setptr(&ptr, newptr)

#define odp_cs_tptr(ptr, old, new) \
	_odp_atomic_tptr_cmp_xchg_strong(&ptr, &old, &new, \
					_ODP_MEMMODEL_SC, \
					_ODP_MEMMODEL_SC)

#define odp_cs_tptr(ptr, old, new) \
	_odp_atomic_tptr_cmp_xchg_strong(&ptr, &old, &new, \
					_ODP_MEMMODEL_SC, \
					_ODP_MEMMODEL_SC)

static inline void flush_cache(local_cache_t *buf_cache,
			       struct pool_entry_s *pool)
{
	odp_buffer_hdr_t *buf = buf_cache->buf_freelist;
	uint32_t flush_count = 0;

	while (buf != NULL) {
		odp_buffer_hdr_t *next = buf->next;
		ret_buf(pool, buf);
		buf = next;
		flush_count++;
	}

	odp_atomic_add_u64(&pool->poolstats.bufallocs, buf_cache->bufallocs);
	odp_atomic_add_u64(&pool->poolstats.buffrees,
			   buf_cache->buffrees - flush_count);

	buf_cache->buf_freelist = NULL;
	buf_cache->bufallocs = 0;
	buf_cache->buffrees = 0;
}

static inline void flush_blk_cache(local_blk_cache_t *blk_cache,
				   struct pool_entry_s *pool)
{
	odp_buf_blk_t *blk = blk_cache->blk_freelist;
	uint32_t flush_count = 0;

	while (blk != NULL) {
		odp_buf_blk_t *next = blk->next;
		ret_blk(pool, blk);
		blk = next;
		flush_count++;
	}

	odp_atomic_add_u64(&pool->poolstats.blkallocs,
			   blk_cache->blkallocs);
	odp_atomic_add_u64(&pool->poolstats.blkfrees,
			   blk_cache->blkfrees - flush_count);

	blk_cache->blk_freelist = NULL;
	blk_cache->blkallocs = 0;
	blk_cache->blkfrees = 0;
}

static inline odp_pool_t pool_index_to_handle(uint32_t pool_id)
{
	return _odp_cast_scalar(odp_pool_t, pool_id);
}

static inline uint32_t pool_handle_to_index(odp_pool_t pool_hdl)
{
	return _odp_typeval(pool_hdl);
}

static inline void *get_pool_entry(uint32_t pool_id)
{
	return pool_entry_ptr[pool_id];
}

static inline pool_entry_t *odp_pool_to_entry(odp_pool_t pool)
{
	return (pool_entry_t *)get_pool_entry(pool_handle_to_index(pool));
}

static inline pool_entry_t *odp_buf_to_pool(odp_buffer_hdr_t *buf)
{
	return odp_pool_to_entry(buf->pool_hdl);
}

static inline uint32_t odp_buffer_pool_segment_size(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->s.seg_size;
}

static inline uint32_t odp_buffer_pool_headroom(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->s.headroom;
}

static inline uint32_t odp_buffer_pool_tailroom(odp_pool_t pool)
{
	return odp_pool_to_entry(pool)->s.tailroom;
}

void _buffer_free(odp_buffer_t buf);
odp_pool_t _pool_create(const char *name,
			odp_pool_param_t *params,
			uint32_t shmflags);

#ifdef __cplusplus
}
#endif

#endif
