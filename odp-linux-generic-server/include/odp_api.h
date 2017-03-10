/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * The OpenDataPlane API
 *
 */

#ifndef ODP_API_H_
#define ODP_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/version.h>
#include <odp/api/std_types.h>
#include <odp/api/compiler.h>
#include <odp/api/align.h>
#include <odp/api/hash.h>
#include <odp/api/hints.h>
#include <odp/api/debug.h>
#include <odp/api/byteorder.h>
#include <odp/api/cpu.h>
#include <odp/api/cpumask.h>
#include <odp/api/barrier.h>
#include <odp/api/spinlock.h>
#include <odp/api/atomic.h>
#include <odp/api/init.h>
#include <odp/api/system_info.h>
#include <odp/api/thread.h>
#include <odp/api/shared_memory.h>
#include <odp/api/buffer.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>
#include <odp/api/ticketlock.h>
#include <odp/api/time.h>
#include <odp/api/timer.h>
#include <odp/api/schedule.h>
#include <odp/api/sync.h>
#include <odp/api/packet.h>
#include <odp/api/packet_flags.h>
#include <odp/api/file_io.h>
#include <odp/api/packet_io.h>
#include <odp/api/socket_io.h>
#include <odp/api/crypto.h>
#include <odp/api/classification.h>
#include <odp/api/rwlock.h>
#include <odp/api/event.h>
#include <odp/api/random.h>
#include <odp/api/errno.h>
#include <odp/api/thrmask.h>
#include <odp/api/traffic_mngr.h>
#include <odp/api/spinlock_recursive.h>
#include <odp/api/rwlock_recursive.h>
#include <odp/api/std_clib.h>

#ifdef __cplusplus
}
#endif
#endif
