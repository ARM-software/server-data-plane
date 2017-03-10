/* Copyright (c) 2017, ARM Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 * 
 * ODP Stream Packetizer Internal
 */

/* Internal helper functions for the packetizer class
 *
 */

#ifndef ODP_STREAM_PACKETIZER_INTERNAL_H_
#define ODP_STREAM_PACKETIZER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/socket_io.h>
#include <odp/api/pool.h>
#include <odp/api/stream_packetizer.h>

//#define PKTIZER_USE_PTHREADLOCK
#define PKTIZER_USE_TICKETLOCK

#ifdef PKTIZER_USE_PTHREADLOCK
#include <odp/api/pthreadlock.h>
#elif defined(PKTIZER_USE_TICKETLOCK)
#include <odp/api/ticketlock.h>
#else
#include <odp/api/spinlock.h>
#endif

// Forward decl
typedef struct odp_packetizer_entry odp_packetizer_entry;
typedef int (*packetizer_func_t)(odp_packet_t, odp_packet_t*, unsigned,
                                 odp_packetizer_entry*);

typedef struct odp_packetizer_entry {
	odp_packetizer_entry_t e;
#ifdef PKTIZER_USE_PTHREADLOCK
	odp_pthreadlock_t lock;
#elif defined(PKTIZER_USE_TICKETLOCK)
	odp_ticketlock_t lock;
#else
	odp_spinlock_t lock; /* Entry spinlock */
#endif
	int taken;
	odp_packet_t input_pkt_buffer;
	int inbuf_offset;
	packetizer_func_t packetizer;
} odp_packetizer_entry;

/* Get the packetizer entry specified by the handle */
odp_packetizer_entry *odp_packetizer_handle_to_context(odp_packetizer_t handle);

/* Get packetizer id assigned to the sockio instance */
odp_packetizer_t odp_sockio_to_packetizer(odp_sockio_t sockio);

/* Get amount of data the sockio should read */
int odp_packetizer_bufferlen(odp_packetizer_t pktizer);

/* Wrapper for sockio instance to run packetizer, interface not completely set
 **/
int odp_run_packetizer(odp_packetizer_t pktizer, odp_packet_t input_pkt,
                       odp_packet_t pkt_table[], unsigned len);

/* Default, proof-of-concept binary packetizer for testing purposes */
int odp_binary_packetizer(odp_packet_t input_pkt,
                          odp_packet_t *pkt_table, unsigned len,
                          odp_packetizer_entry *entry);

#ifdef __cplusplus
}
#endif

#endif
