/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <errno.h>
#include <unistd.h>

#include <odp/api/epoll.h>
#include <odp/api/socket_io.h>

#include <odp_debug_internal.h>
#include <odp_epoll_internal.h>
#include <odp_socket_io_internal.h>

/* 1 global epoll instance for ODP-Server prototype */
odp_epoll_t efd;

int odp_epoll_init_global(void)
{
	int fd;

	fd = epoll_create1(0);
	if (fd < 0) {
		ODP_ERR("Epoll init: failed to create epoll descriptor.\n");
		return -1;
	}

	efd.efd = fd;
	return 0;
}

int odp_epoll_term_global(void)
{
	close(efd.efd);
	efd.efd = -1;
	return 0;
}

int odp_epoll_set_event(odp_event_t evt, int fd, uint32_t epoll_events)
{
	struct epoll_event event;

	event.data.u32 = _odp_typeval(evt);
	event.events = epoll_events;

	if (epoll_ctl(efd.efd, EPOLL_CTL_ADD, fd, &event) < 0) {
		ODP_ERR("Epoll failed to set the event.\n");
		return -1;
	}
	return 0;
}

int odp_epoll_reset_event(odp_event_t evt, int fd, uint32_t epoll_events)
{
	struct epoll_event event;
	event.data.u32 = _odp_typeval(evt);
	event.events = epoll_events;

	if (epoll_ctl(efd.efd, EPOLL_CTL_MOD, fd, &event) < 0) {
		ODP_ERR("Epoll failed to reset the event (%d).\n", errno);
		return -1;
	}
	return 0;
}

int odp_epoll_get_events(odp_event_t *ev, int num, int timeout)
{
	int evts, i;
	odp_event_t evt;
	struct epoll_event events[ODP_MAX_EPOLL_EVENTS];

	/* Get events that are ready now, do not block */
	evts = epoll_wait(efd.efd, events, num, timeout);
	if (evts < 0) {
		ODP_ERR("Epoll returned errno: %d.\n", errno);
		return -1;
	}

	for (i = 0; i < evts; i++) {
		evt = _odp_cast_scalar(odp_event_t, events[i].data.u32);
		ev[i] = evt;
	}
	return evts;
}
