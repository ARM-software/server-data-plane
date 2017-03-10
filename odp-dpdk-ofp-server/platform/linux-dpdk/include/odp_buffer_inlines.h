/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Inline functions for ODP buffer mgmt routines - implementation internal
 */

#ifndef ODP_BUFFER_INLINES_H_
#define ODP_BUFFER_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_errno.h>
#define __odp_errno (rte_errno)

#include <odp_buffer_internal.h>

#define UNUSED __attribute__((__unused__))

static inline odp_buffer_t odp_hdr_to_buf(odp_buffer_hdr_t *hdr)
{
	return (odp_buffer_t)hdr;
}

static inline odp_buffer_hdr_t *odp_buf_to_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)(void *)buf;
}

static inline odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf)
{
	return odp_buf_to_hdr(buf)->event_type;
}

static inline void _odp_buffer_event_type_set(odp_buffer_t buf, int ev)
{
	odp_buf_to_hdr(buf)->event_type = ev;
}

static inline void *buffer_map(odp_buffer_hdr_t *buf,
			       uint32_t offset,
			       uint32_t *seglen,
			       uint32_t limit UNUSED)
{
	struct rte_mbuf *mb = &(buf->mb);

	while (mb) {
		if (mb->data_len > offset) {
			break;
		} else {
			offset -= mb->data_len;
			mb = mb->next;
		}
	}

	if (mb) {
		if (seglen)
			*seglen = mb->data_len - offset;
		return (void *)(rte_pktmbuf_mtod(mb, char *) + offset);
	} else {
		return NULL;
	}
}
#ifdef __cplusplus
}
#endif

#endif
