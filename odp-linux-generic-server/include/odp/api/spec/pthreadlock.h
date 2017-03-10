/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP pthread lock
 */

#ifndef ODP_PTHREADLOCK_H_
#define ODP_PTHREADLOCK_H_

#include <pthread.h>
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/***
 * If running ODP in user-space, the ticket and spinlocks are
 * in danger of live-locking the system due to the kernel suspending
 * threads in the middle of atomic operations. Pthread locks, are
 * slower but keep the system usable when doing testing.
 */

typedef struct odp_pthreadlock_t {
	pthread_mutex_t lock;
} odp_pthreadlock_t;

void odp_pthreadlock_init(odp_pthreadlock_t *plock);

void odp_pthreadlock_lock(odp_pthreadlock_t *plock);

int odp_pthreadlock_trylock(odp_pthreadlock_t *plock);

void odp_pthreadlock_unlock(odp_pthreadlock_t *plock);

int odp_pthreadlock_is_locked(odp_pthreadlock_t *plock);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif
