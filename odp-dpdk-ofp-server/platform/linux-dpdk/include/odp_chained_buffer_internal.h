/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * Internal function declarations for working with chained buffers
 */

#ifndef ODP_CHAINED_BUFFER_INTERNAL_H_
#define ODP_CHAINED_BUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_packet_dpdk.h>

static inline int odp_chained_buffer_num_segs(odp_buffer_t buf)
{
	int i = 1;
	struct rte_mbuf *mb;
	mb = &(odp_buf_to_hdr(buf)->mb);

	while (mb->next != NULL) {
		mb = mb->next;
		i++;
	}

	return i;
}

#ifdef __cplusplus
}
#endif
#endif
