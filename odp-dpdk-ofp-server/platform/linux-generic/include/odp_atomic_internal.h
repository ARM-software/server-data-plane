/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP atomic types and operations, semantically a subset of C11 atomics.
 * Reuse the 32-bit and 64-bit type definitions from odp_atomic.h. Introduces
 * new atomic pointer and flag types.
 * Atomic functions must be used to operate on atomic variables!
 */

#ifndef ODP_ATOMIC_INTERNAL_H_
#define ODP_ATOMIC_INTERNAL_H_

#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/atomic.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Pointer atomic type
 */
typedef struct {
	void *v; /**< Actual storage for the atomic variable */
} _odp_atomic_ptr_t
ODP_ALIGNED(sizeof(void *)); /* Enforce alignement! */

/**
 * Opaque tagged pointer atomic type
 */
#if PTRDIFF_MAX == 8
#if defined __SIZEOF_INT128__ && defined __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16
#define ODP_64BIT_HAVE_CMPX16
/* Our system is 64bit and has cmpx16 support */
typedef union {
       __uint128_t v;
       struct {
               uint64_t tag;
               void *ptr;
       } tptr;
} _odp_atomic_tptr_t
ODP_ALIGNED(sizeof(__int128));
#else
/* Fallback path for 64bit archs without cmpx16 */
typedef struct {
       char lock;
       struct {
               uint64_t tag;
               void *ptr;
       } tptr;
} _odp_atomic_tptr_t
ODP_ALIGNED(16);
#endif
#else
#if defined __GCC_ATOMIC_LLONG_LOCK_FREE && __GCC_ATOMIC_LLONG_LOCK_FREE >= 2
#define ODP_32BIT_HAVE_CMPX8
/* Our system is 32bit and has cmpx8 support */
typedef union {
       uint64_t v;
       struct {
               uint32_t tag;
               void *ptr;
       } tptr;
} _odp_atomic_tptr_t
ODP_ALIGNED(sizeof(uint64_t));
#else
/* Fallback path for 32bit archs without cmpx8 support */
typedef struct {
       char lock;
       struct {
               uint32_t tag;
               void *ptr;
       } tptr;
} _odp_atomic_tptr_t
ODP_ALIGNED(sizeof(uint64_t));
#endif
#endif

/**
 * Atomic flag (boolean) type
 * @Note this is not the same as a plain boolean type.
 * _odp_atomic_flag_t is guaranteed to be able to operate on atomically.
 */
typedef char _odp_atomic_flag_t;

/**
 * Memory orderings supported by ODP.
 */
typedef enum {
/** Relaxed memory ordering, no ordering of other accesses enforced.
 * Atomic operations with relaxed memory ordering cannot be used for
 * synchronization */
	_ODP_MEMMODEL_RLX = __ATOMIC_RELAXED,
/** Acquire memory ordering, synchronize with release stores from another
 * thread (later accesses cannot move before acquire operation).
 * Use acquire and release memory ordering for Release Consistency */
	_ODP_MEMMODEL_ACQ = __ATOMIC_ACQUIRE,
/** Release memory ordering, synchronize with acquire loads from another
 * thread (earlier accesses cannot move after release operation).
 * Use acquire and release memory ordering for Release Consistency */
	_ODP_MEMMODEL_RLS = __ATOMIC_RELEASE,
/** Acquire&release memory ordering, synchronize with acquire loads and release
 * stores in another (one other) thread */
	_ODP_MEMMODEL_ACQ_RLS = __ATOMIC_ACQ_REL,
/** Sequential consistent memory ordering, synchronize with acquire loads and
 * release stores in all threads */
	_ODP_MEMMODEL_SC = __ATOMIC_SEQ_CST
} _odp_memmodel_t;

/*****************************************************************************
 * Operations on 32-bit atomics
 * _odp_atomic_u32_load_mm - return current value
 * _odp_atomic_u32_store_mm - no return value
 * _odp_atomic_u32_xchg_mm - return old value
 * _odp_atomic_u32_cmp_xchg_strong_mm - return bool
 * _odp_atomic_u32_fetch_add_mm - return old value
 * _odp_atomic_u32_add_mm - no return value
 * _odp_atomic_u32_fetch_sub_mm - return old value
 * _odp_atomic_u32_sub_mm - no return value
 *****************************************************************************/

/**
 * Atomic load of 32-bit atomic variable
 *
 * @param atom Pointer to a 32-bit atomic variable
 * @param mmodel Memory ordering associated with the load operation
 *
 * @return Value of the variable
 */
static inline uint32_t _odp_atomic_u32_load_mm(const odp_atomic_u32_t *atom,
		_odp_memmodel_t mmodel)
{
	return __atomic_load_n(&atom->v, mmodel);
}

/**
 * Atomic store to 32-bit atomic variable
 *
 * @param[out] atom Pointer to a 32-bit atomic variable
 * @param val    Value to store in the atomic variable
 * @param mmodel Memory order associated with the store operation
 */
static inline void _odp_atomic_u32_store_mm(odp_atomic_u32_t *atom,
		uint32_t val,
		_odp_memmodel_t mmodel)
{
	__atomic_store_n(&atom->v, val, mmodel);
}

/**
 * Atomic exchange (swap) of 32-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 32-bit atomic variable
 * @param val    New value to store in the atomic variable
 * @param mmodel Memory order associated with the exchange operation
 *
 * @return Old value of the variable
 */
static inline uint32_t _odp_atomic_u32_xchg_mm(odp_atomic_u32_t *atom,
		uint32_t val,
		_odp_memmodel_t mmodel)

{
	return __atomic_exchange_n(&atom->v, val, mmodel);
}

/**
 * Atomic compare and exchange (swap) of 32-bit atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param[in,out] atom Pointer to a 32-bit atomic variable
 * @param[in,out] exp Pointer to expected value (updated on failure)
 * @param val   New value to write
 * @param success Memory order associated with a successful compare-and-swap
 * operation
 * @param failure Memory order associated with a failed compare-and-swap
 * operation
 *
 * @retval 1 exchange successul
 * @retval 0 exchange failed and '*exp' updated with current value
 */
static inline int _odp_atomic_u32_cmp_xchg_strong_mm(
		odp_atomic_u32_t *atom,
		uint32_t *exp,
		uint32_t val,
		_odp_memmodel_t success,
		_odp_memmodel_t failure)
{
	return __atomic_compare_exchange_n(&atom->v, exp, val,
			false/*strong*/, success, failure);
}

/**
 * Atomic fetch and add of 32-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 32-bit atomic variable
 * @param val Value to add to the atomic variable
 * @param mmodel Memory order associated with the add operation
 *
 * @return Value of the atomic variable before the addition
 */
static inline uint32_t _odp_atomic_u32_fetch_add_mm(odp_atomic_u32_t *atom,
		uint32_t val,
		_odp_memmodel_t mmodel)
{
	return __atomic_fetch_add(&atom->v, val, mmodel);
}

/**
 * Atomic add of 32-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 32-bit atomic variable
 * @param val Value to add to the atomic variable
 * @param mmodel Memory order associated with the add operation
 */
static inline void _odp_atomic_u32_add_mm(odp_atomic_u32_t *atom,
		uint32_t val,
		_odp_memmodel_t mmodel)

{
	(void)__atomic_fetch_add(&atom->v, val, mmodel);
}

/**
 * Atomic fetch and subtract of 32-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 32-bit atomic variable
 * @param val Value to subtract from the atomic variable
 * @param mmodel Memory order associated with the subtract operation
 *
 * @return Value of the atomic variable before the subtraction
 */
static inline uint32_t _odp_atomic_u32_fetch_sub_mm(odp_atomic_u32_t *atom,
		uint32_t val,
		_odp_memmodel_t mmodel)
{
	return __atomic_fetch_sub(&atom->v, val, mmodel);
}

/**
 * Atomic subtract of 32-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 32-bit atomic variable
 * @param val Value to subtract from the atomic variable
 * @param mmodel Memory order associated with the subtract operation
 */
static inline void _odp_atomic_u32_sub_mm(odp_atomic_u32_t *atom,
		uint32_t val,
		_odp_memmodel_t mmodel)

{
	(void)__atomic_fetch_sub(&atom->v, val, mmodel);
}

/*****************************************************************************
 * Operations on 64-bit atomics
 * _odp_atomic_u64_load_mm - return current value
 * _odp_atomic_u64_store_mm - no return value
 * _odp_atomic_u64_xchg_mm - return old value
 * _odp_atomic_u64_cmp_xchg_strong_mm - return bool
 * _odp_atomic_u64_fetch_add_mm - return old value
 * _odp_atomic_u64_add_mm - no return value
 * _odp_atomic_u64_fetch_sub_mm - return old value
 * _odp_atomic_u64_sub_mm - no return value
 *****************************************************************************/

/* Check if the compiler support lock-less atomic operations on 64-bit types */
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
/**
 * @internal
 * Helper macro for lock-based atomic operations on 64-bit integers
 * @param[in,out] atom Pointer to the 64-bit atomic variable
 * @param expr Expression used update the variable.
 * @param mm Memory order to use.
 * @return The old value of the variable.
 */
#define ATOMIC_OP_MM(atom, expr, mm) \
({ \
	 uint64_t old_val; \
	 /* Loop while lock is already taken, stop when lock becomes clear */ \
	 while (__atomic_test_and_set(&(atom)->lock, \
		(mm) == _ODP_MEMMODEL_SC ? \
		__ATOMIC_SEQ_CST : __ATOMIC_ACQUIRE)) \
		(void)0; \
	 old_val = (atom)->v; \
	 (expr); /* Perform whatever update is desired */ \
	 __atomic_clear(&(atom)->lock, \
		 (mm) == _ODP_MEMMODEL_SC ? \
		 __ATOMIC_SEQ_CST : __ATOMIC_RELEASE); \
	 old_val; /* Return old value */ \
})
#endif

/**
 * Atomic load of 64-bit atomic variable
 *
 * @param atom Pointer to a 64-bit atomic variable
 * @param mmodel Memory order associated with the load operation
 *
 * @return Value of the variable
 */
static inline uint64_t _odp_atomic_u64_load_mm(odp_atomic_u64_t *atom,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(atom, (void)0, mmodel);
#else
	return __atomic_load_n(&atom->v, mmodel);
#endif
}

/**
 * Atomic store to 64-bit atomic variable
 *
 * @param[out] atom Pointer to a 64-bit atomic variable
 * @param val  Value to write to the atomic variable
 * @param mmodel Memory order associated with the store operation
 */
static inline void _odp_atomic_u64_store_mm(odp_atomic_u64_t *atom,
		uint64_t val,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP_MM(atom, atom->v = val, mmodel);
#else
	__atomic_store_n(&atom->v, val, mmodel);
#endif
}

/**
 * Atomic exchange (swap) of 64-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 64-bit atomic variable
 * @param val   New value to write to the atomic variable
 * @param mmodel Memory order associated with the exchange operation
 *
 * @return Old value of variable
 */
static inline uint64_t _odp_atomic_u64_xchg_mm(odp_atomic_u64_t *atom,
		uint64_t val,
		_odp_memmodel_t mmodel)

{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(atom, atom->v = val, mmodel);
#else
	return __atomic_exchange_n(&atom->v, val, mmodel);
#endif
}

/**
 * Atomic compare and exchange (swap) of 64-bit atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param[in,out] atom Pointer to a 64-bit atomic variable
 * @param[in,out] exp Pointer to expected value (updated on failure)
 * @param val   New value to write
 * @param success Memory order associated with a successful compare-and-swap
 * operation
 * @param failure Memory order associated with a failed compare-and-swap
 * operation
 *
 * @retval 1 exchange successful
 * @retval 0 exchange failed and '*exp' updated with current value
 */
static inline int _odp_atomic_u64_cmp_xchg_strong_mm(odp_atomic_u64_t *atom,
		uint64_t *exp,
		uint64_t val,
		_odp_memmodel_t success,
		_odp_memmodel_t failure)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	/* Possibly we are a bit pessimistic with the memory models */
	odp_bool_t ret_succ;
	/* Loop while lock is already taken, stop when lock becomes clear */
	while (__atomic_test_and_set(&(atom)->lock,
		(success) == _ODP_MEMMODEL_SC ?
		__ATOMIC_SEQ_CST : __ATOMIC_ACQUIRE))
		(void)0;
	if (atom->v == *exp) {
		atom->v = val;
		ret_succ = 1;
	} else {
		*exp = atom->v;
		ret_succ = 0;
	}
	__atomic_clear(&(atom)->lock,
		       (ret_succ ? success : failure) == _ODP_MEMMODEL_SC ?
		       __ATOMIC_SEQ_CST : __ATOMIC_RELEASE);
	return ret_succ;
#else
	return __atomic_compare_exchange_n(&atom->v, exp, val,
			false/*strong*/, success, failure);
#endif
}

/**
 * Atomic fetch and add of 64-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 64-bit atomic variable
 * @param val   Value to add to the atomic variable
 * @param mmodel Memory order associated with the add operation
 *
 * @return Value of the atomic variable before the addition
 */
static inline uint64_t _odp_atomic_u64_fetch_add_mm(odp_atomic_u64_t *atom,
		uint64_t val,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(atom, atom->v += val, mmodel);
#else
	return __atomic_fetch_add(&atom->v, val, mmodel);
#endif
}

/**
 * Atomic add of 64-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 64-bit atomic variable
 * @param val   Value to add to the atomic variable
 * @param mmodel Memory order associated with the add operation.
 */
static inline void _odp_atomic_u64_add_mm(odp_atomic_u64_t *atom,
		uint64_t val,
		_odp_memmodel_t mmodel)

{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP_MM(atom, atom->v += val, mmodel);
#else
	(void)__atomic_fetch_add(&atom->v, val, mmodel);
#endif
}

/**
 * Atomic fetch and subtract of 64-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 64-bit atomic variable
 * @param val   Value to subtract from the atomic variable
 * @param mmodel Memory order associated with the subtract operation
 *
 * @return Value of the atomic variable before the subtraction
 */
static inline uint64_t _odp_atomic_u64_fetch_sub_mm(odp_atomic_u64_t *atom,
		uint64_t val,
		_odp_memmodel_t mmodel)
{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	return ATOMIC_OP_MM(atom, atom->v -= val, mmodel);
#else
	return __atomic_fetch_sub(&atom->v, val, mmodel);
#endif
}

/**
 * Atomic subtract of 64-bit atomic variable
 *
 * @param[in,out] atom Pointer to a 64-bit atomic variable
 * @param val   Value to subtract from the atomic variable
 * @param mmodel Memory order associated with the subtract operation
 */
static inline void _odp_atomic_u64_sub_mm(odp_atomic_u64_t *atom,
		uint64_t val,
		_odp_memmodel_t mmodel)

{
#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	(void)ATOMIC_OP_MM(atom, atom->v -= val, mmodel);
#else
	(void)__atomic_fetch_sub(&atom->v, val, mmodel);
#endif
}

#if !defined __GCC_ATOMIC_LLONG_LOCK_FREE ||  __GCC_ATOMIC_LLONG_LOCK_FREE < 2
#undef ATOMIC_OP_MM
#endif

/*****************************************************************************
 * Operations on pointer atomics
 * _odp_atomic_ptr_init - no return value
 * _odp_atomic_ptr_load - return current value
 * _odp_atomic_ptr_store - no return value
 * _odp_atomic_ptr_xchg - return old value
 *****************************************************************************/

/**
 * Initialization of pointer atomic variable
 *
 * @param[out] atom Pointer to a pointer atomic variable
 * @param val   Value to initialize the variable with
 */
static inline void _odp_atomic_ptr_init(_odp_atomic_ptr_t *atom, void *val)
{
	__atomic_store_n(&atom->v, val, __ATOMIC_RELAXED);
}

/**
 * Atomic load of pointer atomic variable
 *
 * @param atom Pointer to a pointer atomic variable
 * @param mmodel Memory order associated with the load operation
 *
 * @return Value of the variable
 */
static inline void *_odp_atomic_ptr_load(const _odp_atomic_ptr_t *atom,
		_odp_memmodel_t mmodel)
{
	return __atomic_load_n(&atom->v, mmodel);
}

/**
 * Atomic store to pointer atomic variable
 *
 * @param[out] atom Pointer to a pointer atomic variable
 * @param val  Value to write to the atomic variable
 * @param mmodel Memory order associated with the store operation
 */
static inline void _odp_atomic_ptr_store(_odp_atomic_ptr_t *atom,
		void *val,
		_odp_memmodel_t mmodel)
{
	__atomic_store_n(&atom->v, val, mmodel);
}

/**
 * Atomic exchange (swap) of pointer atomic variable
 *
 * @param[in,out] atom Pointer to a pointer atomic variable
 * @param val   New value to write
 * @param mmodel Memory order associated with the exchange operation
 *
 * @return Old value of variable
 */
static inline void *_odp_atomic_ptr_xchg(_odp_atomic_ptr_t *atom,
		void *val,
		_odp_memmodel_t mmodel)
{
	return __atomic_exchange_n(&atom->v, val, mmodel);
}

/**
 * Atomic compare and exchange (swap) of pointer atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param[in,out] atom Pointer to a pointer atomic variable
 * @param[in,out] exp Pointer to expected value (updated on failure)
 * @param val   New value to write
 * @param success Memory order associated with a successful compare-and-swap
 * operation
 * @param failure Memory order associated with a failed compare-and-swap
 * operation
 *
 * @retval 1 exchange successful
 * @retval 0 exchange failed and '*exp' updated with current value
 */
static inline int _odp_atomic_ptr_cmp_xchg_strong(
		_odp_atomic_ptr_t *atom,
		void **exp,
		void *val,
		_odp_memmodel_t success,
		_odp_memmodel_t failure)
{
	return __atomic_compare_exchange_n(&atom->v, exp, val,
			false/*strong*/, success, failure);
}

/****************************************************************************
 * Operations on tagged pointer atomics
 * _odp_atomic_tptr_init - no return value
 * _odp_atomic_tptr_load - return current value
 * _odp_atomic_tptr_store - no return value
 * _odp_atomic_tptr_xchg - return old value
 * _odp_atomic_tptr_gettag - return tag value
 * _odp_atomic_tptr_settag - no return value
 * _odp_atomic_tptr_getptr - return pointer value
 * _odp_atomic_tptr_setptr - no return value
 *****************************************************************************/
#if !defined ODP_64BIT_HAVE_CMPX16 && !defined ODP_32BIT_HAVE_CMPX8
/**
 * @internal
 * Helper macro for lock-based atomic operations on 128/64-bit tagged pointers
 * @param[in,out] atom Pointer to the atomic tagged pointer variable
 * @param expr Expression used update the variable.
 * @param mm Memory order to use.
 * @return The old value of the variable.
 */
#define ATOMIC_TPTR_OP_MM(atom, expr, mm) \
({ \
	 _odp_atomic_tptr_t old_val; \
	 /* Loop while lock is already taken, stop when lock becomes clear */ \
	 while (__atomic_test_and_set(&(atom)->lock, \
		(mm) == _ODP_MEMMODEL_SC ? \
		__ATOMIC_SEQ_CST : __ATOMIC_ACQUIRE)) \
		(void)0; \
	 old_val.tptr = (atom->tptr); \
	 (expr); /* Perform whatever update is desired */ \
	 __atomic_clear(&(atom)->lock, \
		 (mm) == _ODP_MEMMODEL_SC ? \
		 __ATOMIC_SEQ_CST : __ATOMIC_RELEASE); \
	 __atomic_clear(&(old_val).lock, \
		 (mm) == _ODP_MEMMODEL_SC ? \
		 __ATOMIC_SEQ_CST : __ATOMIC_RELEASE); \
	 old_val; /* Return old value */ \
})
#endif

/**
 * Initialization of a tagged pointer atomic variable
 *
 * @param[out] atom Pointer to a pointer atomic variable
 * @param val   Value to initialize the variable with
 */
static inline void _odp_atomic_tptr_init(_odp_atomic_tptr_t *atom, void *val)
{
	__atomic_store_n(&atom->tptr.ptr, val, __ATOMIC_RELAXED);
	__atomic_store_n(&atom->tptr.tag, 0, __ATOMIC_RELAXED);
#if !defined ODP_64BIT_HAVE_CMPX16 && !defined ODP_32BIT_HAVE_CMPX8
	__atomic_clear(&atom->lock, __ATOMIC_RELAXED);
#endif
}

/**
 * Atomic load of a tagged pointer atomic variable
 *
 * @param atom Tagged pointer to a pointer atomic variable
 * @param mmodel Memory order associated with the load operation
 *
 * @return Value of the variable
 */
static inline _odp_atomic_tptr_t _odp_atomic_tptr_load(_odp_atomic_tptr_t *atom,
						       _odp_memmodel_t mmodel)
{
#if defined ODP_64BIT_HAVE_CMPX16 || defined ODP_32BIT_HAVE_CMPX8
	_odp_atomic_tptr_t ret;
	ret.v = __atomic_load_n(&atom->v, mmodel);
	return ret;
#else
	return ATOMIC_TPTR_OP_MM(atom, (void)0, mmodel);
#endif
}

/**
 * Atomic store to a tagged pointer atomic variable
 *
 * @param[out] atom Tagged pointer to a pointer atomic variable
 * @param val  Value to write to the atomic variable
 * @param mmodel Memory order associated with the store operation
 */
static inline void _odp_atomic_tptr_store(_odp_atomic_tptr_t *atom,
					  _odp_atomic_tptr_t *val,
					  _odp_memmodel_t mmodel)
{
#if defined ODP_64BIT_HAVE_CMPX16 || defined ODP_32BIT_HAVE_CMPX8
	__atomic_store_n(&atom->v, val->v, mmodel);
#else
	ATOMIC_TPTR_OP_MM(atom, atom->tptr = val->tptr, mmodel);
#endif
}

/**
 * Atomic exchange (swap) of tagged pointer atomic variable
 *
 * @param[in,out] atom Tagged pointer to a pointer atomic variable
 * @param val   New value to write
 * @param mmodel Memory order associated with the exchange operation
 *
 * @return Old value of variable
 */
static inline _odp_atomic_tptr_t _odp_atomic_tptr_xchg(_odp_atomic_tptr_t *atom,
						       _odp_atomic_tptr_t *val,
						       _odp_memmodel_t mmodel)
{
#if defined ODP_64BIT_HAVE_CMPX16 || defined ODP_32BIT_HAVE_CMPX8
	_odp_atomic_tptr_t ret;
	ret.v = __atomic_exchange_n(&atom->v, val->v, mmodel);
	return ret;
#else
	return ATOMIC_TPTR_OP_MM(atom, atom->tptr = val->tptr, mmodel);
#endif
}

/**
 * Atomic compare and exchange (swap) of pointer atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param[in,out] atom Pointer to a pointer atomic variable
 * @param[in,out] exp Pointer to expected value (updated on failure)
 * @param val   New value to write
 * @param success Memory order associated with a successful compare-and-swap
 * operation
 * @param failure Memory order associated with a failed compare-and-swap
 * operation
 *
 * @retval 1 exchange successful
 * @retval 0 exchange failed and '*exp' updated with current value
 */
static inline int _odp_atomic_tptr_cmp_xchg_strong(
		_odp_atomic_tptr_t *atom,
		_odp_atomic_tptr_t *exp,
		_odp_atomic_tptr_t *val,
		_odp_memmodel_t success,
		_odp_memmodel_t failure)
{
#if defined ODP_64BIT_HAVE_CMPX16 || defined ODP_32BIT_HAVE_CMPX8
	return __atomic_compare_exchange_n(&atom->v, &exp->v, val->v,
			false/*strong*/, success, failure);
#else
	/* Possibly we are a bit pessimistic with the memory models */
	odp_bool_t ret_succ;
	/* Loop while lock is already taken, stop when lock becomes clear */
	while (__atomic_test_and_set(&(atom)->lock,
		(success) == _ODP_MEMMODEL_SC ?
		__ATOMIC_SEQ_CST : __ATOMIC_ACQUIRE))
		(void)0;
	if (atom->tptr.tag == exp->tptr.tag &&
	    atom->tptr.ptr == exp->tptr.ptr) {
		atom->tptr = val->tptr;
		ret_succ = 1;
	} else {
		exp->tptr = atom->tptr;
		ret_succ = 0;
	}
	__atomic_clear(&(atom)->lock,
		       (ret_succ ? success : failure) == _ODP_MEMMODEL_SC ?
		       __ATOMIC_SEQ_CST : __ATOMIC_RELEASE);
	return ret_succ;
#endif
}

/**
 * Non-atomically get the tag from the tagged pointer datastructure
 *
 * @param tptr The tagged pointer to extract the tag from
 *
 * @retval Current value of the tag
 */
#if PTRDIFF_MAX == 8
static inline uint64_t _odp_atomic_tptr_gettag(_odp_atomic_tptr_t *tptr)
#else
static inline uint32_t _odp_atomic_tptr_gettag(_odp_atomic_tptr_t *tptr)
#endif
{
	return tptr->tptr.tag;
}

/**
 * Non-atomically update the tag of the tagged pointer datastructure
 *
 * @param tptr The tagged pointer datastructure to set the tag on
 * @param tag  The value to set the tag to
 */
#if PTRDIFF_MAX == 8
static inline void _odp_atomic_tptr_settag(_odp_atomic_tptr_t *tptr,
					   uint64_t tag)
#else
static inline void _odp_atomic_tptr_settag(_odp_atomic_tptr_t *tptr,
					   uint32_t tag)
#endif
{
	tptr->tptr.tag = tag;
}

/**
 * Non-atomically extract the pointer contained in the tagged pointer
 * datastructure
 *
 * @param tptr The tagged pointer datastructure to extract the pointer from
 *
 * @return Current pointer value
 */
static inline void *_odp_atomic_tptr_getptr(_odp_atomic_tptr_t *tptr)
{
	return tptr->tptr.ptr;
}

/**
 * Non-atomically set the pointer value contained in the tagged pointer
 *
 * @param tptr The tagged pointer datastructure to set the pointer to
 * @param ptr  The pointer value to set
 */
static inline void _odp_atomic_tptr_setptr(_odp_atomic_tptr_t *tptr,
						 void *ptr)
{
	tptr->tptr.ptr = ptr;
}

/*****************************************************************************
 * Operations on flag atomics
 * _odp_atomic_flag_init - no return value
 * _odp_atomic_flag_load - return current value
 * _odp_atomic_flag_tas - return old value
 * _odp_atomic_flag_clear - no return value
 *
 * Flag atomics use Release Consistency memory consistency model, acquire
 * semantics for TAS and release semantics for clear.
 *****************************************************************************/

/**
 * Initialize a flag atomic variable
 *
 * @param[out] flag Pointer to a flag atomic variable
 * @param val The initial value of the variable
 */
static inline void _odp_atomic_flag_init(_odp_atomic_flag_t *flag,
		odp_bool_t val)
{
	__atomic_clear(flag, __ATOMIC_RELAXED);
	if (val)
		__atomic_test_and_set(flag, __ATOMIC_RELAXED);
}

/**
 * Load atomic flag variable
 * @Note Operation has relaxed semantics.
 *
 * @param flag Pointer to a flag atomic variable
 * @return The current value of the variable
 */
static inline int _odp_atomic_flag_load(_odp_atomic_flag_t *flag)
{
	return __atomic_load_n(flag, __ATOMIC_RELAXED);
}

/**
 * Test-and-set of atomic flag variable
 * @Note Operation has acquire semantics. It pairs with a later
 * release operation.
 *
 * @param[in,out] flag Pointer to a flag atomic variable
 *
 * @retval 1 if the flag was already true - lock not taken
 * @retval 0 if the flag was false and is now set to true - lock taken
 */
static inline int _odp_atomic_flag_tas(_odp_atomic_flag_t *flag)
{
	return __atomic_test_and_set(flag, __ATOMIC_ACQUIRE);
}

/**
 * Clear atomic flag variable
 * The flag variable is cleared (set to false).
 * @Note Operation has release semantics. It pairs with an earlier
 * acquire operation or a later load operation.
 *
 * @param[out] flag Pointer to a flag atomic variable
 */
static inline void _odp_atomic_flag_clear(_odp_atomic_flag_t *flag)
{
	__atomic_clear(flag, __ATOMIC_RELEASE);
}

/* Check if target and compiler supports 128-bit scalars and corresponding
 * exchange and CAS operations */
/* GCC/clang on x86-64 needs -mcx16 compiler option */
#if defined __SIZEOF_INT128__ && defined __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16

#if defined(__clang__)

#if ((__clang_major__ * 100 +  __clang_minor__) >= 306)
#define ODP_ATOMIC_U128
#endif

#else /* gcc */
#define ODP_ATOMIC_U128
#endif
#endif

#ifdef ODP_ATOMIC_U128
/** An unsigned 128-bit (16-byte) scalar type */
typedef __int128 _uint128_t;

/** Atomic 128-bit type */
typedef struct {
	_uint128_t v; /**< Actual storage for the atomic variable */
} _odp_atomic_u128_t ODP_ALIGNED(16);

/**
 * 16-byte atomic exchange operation
 *
 * @param ptr   Pointer to a 16-byte atomic variable
 * @param val   Pointer to new value to write
 * @param old   Pointer to location for old value
 * @param       mmodel Memory model associated with the exchange operation
 */
static inline void _odp_atomic_u128_xchg_mm(_odp_atomic_u128_t *ptr,
					    _uint128_t *val,
		_uint128_t *old,
		_odp_memmodel_t mm)
{
	__atomic_exchange(&ptr->v, val, old, mm);
}

/**
 * Atomic compare and exchange (swap) of 16-byte atomic variable
 * "Strong" semantics, will not fail spuriously.
 *
 * @param ptr   Pointer to a 16-byte atomic variable
 * @param exp   Pointer to expected value (updated on failure)
 * @param val   Pointer to new value to write
 * @param succ  Memory model associated with a successful compare-and-swap
 * operation
 * @param fail  Memory model associated with a failed compare-and-swap
 * operation
 *
 * @retval 1 exchange successul
 * @retval 0 exchange failed and '*exp' updated with current value
 */
static inline int _odp_atomic_u128_cmp_xchg_mm(_odp_atomic_u128_t *ptr,
					       _uint128_t *exp,
					       _uint128_t *val,
					       _odp_memmodel_t succ,
					       _odp_memmodel_t fail)
{
	return __atomic_compare_exchange(&ptr->v, exp, val,
			false/*strong*/, succ, fail);
}
#endif

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
