/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Epoll
 */

#ifndef ODP_PLAT_EPOLL_H_
#define ODP_PLAT_EPOLL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/event_types.h>
#include <odp/api/plat/socket_io_types.h>

/** @ingroup
 *  Operations to let ODP use epoll to do more
 *  appropriate scheduling
 *  @{
 */

/**
 * @}
 */

typedef struct odp_epoll_t {
	int efd;
} odp_epoll_t;

#include <odp/api/spec/epoll.h>

#ifdef __cplusplus
}
#endif

#endif
