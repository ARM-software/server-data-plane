/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/pthreadlock.h>
#include <odp_debug_internal.h>

void odp_pthreadlock_init(odp_pthreadlock_t *pthreadlock)
{
	if (pthread_mutex_init(&pthreadlock->lock, NULL) != 0) {
		ODP_ERR("Failed to initialize a pthread mutex!\n");
	}
}

void odp_pthreadlock_lock(odp_pthreadlock_t *pthreadlock)
{
	if (pthread_mutex_lock(&pthreadlock->lock) != 0) {
		ODP_ERR("Failed to lock the pthread mutex!\n");
	}
}

int odp_pthreadlock_trylock(odp_pthreadlock_t *pthreadlock)
{
	if (pthread_mutex_trylock(&pthreadlock->lock) != 0) {
		return 0;
	}
	return 1;
}

void odp_pthreadlock_unlock(odp_pthreadlock_t *pthreadlock)
{
	if (pthread_mutex_unlock(&pthreadlock->lock) != 0) {
		ODP_ERR("Failed to unlock a pthread mutex!\n");
	}
}

/* Just say the lock is not taken */
int odp_pthreadlock_is_locked(odp_pthreadlock_t *pthreadlock)
{
	(void)pthreadlock;
	return 0;
}
