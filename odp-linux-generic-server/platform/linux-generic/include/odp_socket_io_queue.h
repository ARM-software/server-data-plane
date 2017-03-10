/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet IO - implementation internal
 */

#ifndef ODP_SOCKET_IO_QUEUE_H_
#define ODP_SOCKET_IO_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_queue_internal.h>
#include <odp_buffer_internal.h>

/** Max nbr of pkts to receive in one burst (keep same as QUEUE_MULTI_MAX) */
//#define ODP_SOCKIN_QUEUE_MAX_BURST (512) /*16*/

/* pktin_deq_multi() depends on the condition: */
//ODP_STATIC_ASSERT(ODP_SOCKIN_QUEUE_MAX_BURST >= QUEUE_MULTI_MAX,
//	   "ODP_SOCKIN_DEQ_MULTI_MAX_ERROR");

// Input socket queue input and output functions. Only input is supported.
int sockin_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr, int sustain);
odp_buffer_hdr_t *sockin_dequeue(queue_entry_t *queue);

int sockin_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
		     int num, int sustain);
int sockin_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);

// Output socket queue input and output functions.  Only output is supported.
int sockout_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *sockout_dequeue(queue_entry_t *queue);

int sockout_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
		     int num);
int sockout_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
		     int num);

// Listening socket queue input and output functions.  Only input is supported.
int listen_sockin_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr,
			  int sustain);
odp_buffer_hdr_t *listen_sockin_dequeue(queue_entry_t *queue);

int listen_sockin_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			    int num, int sustain);
int listen_sockin_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			    int num);
#ifdef __cplusplus
}
#endif

#endif
