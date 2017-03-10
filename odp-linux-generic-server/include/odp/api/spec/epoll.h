/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:      BSD-3-Clause
 */


/**
 * @file
 *
 * ODP epoll
 */

#ifndef ODP_EPOLL_H_
#define ODP_EPOLL_H_

#include <sys/epoll.h>

#include <odp/api/spec/event.h>
#include <odp/api/spec/socket_io.h>
#include <odp/api/spec/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/****
 * Define an interface to Linux Epoll() to use in conjunction
 * with socket_io queues to allow for scheduling on these queues
 * to be closer to O(ready) in processing time instead of O(N)
 */

/* Allow epoll to monitor for any ready events on the passed in set
 * of fd's and with the specified event flags.
 */
int odp_epoll_set_event(odp_event_t evt, int fd, uint32_t epoll_events);
int odp_epoll_reset_event(odp_event_t evt, int fd, uint32_t epoll_events);

/* Stick events onto an ODP queue for later servicing */
int odp_epoll_get_events(odp_event_t *evs, int num, int timeout);

#ifdef __cplusplus
}
#endif

#endif
