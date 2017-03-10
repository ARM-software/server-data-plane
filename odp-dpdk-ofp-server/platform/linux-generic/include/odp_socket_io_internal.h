/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @ file
 *
 * ODP Socket IO - implementation internal
 */

#ifndef ODP_SOCKET_IO_INTERNAL_H_
#define ODP_SOCKET_IO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/socket_io.h>

#include <odp_align_internal.h>

#define SOCKIO_USE_TICKETLOCK

#ifdef SOCKIO_USE_PTHREADLOCK
#include <odp/api/pthreadlock.h>
#elif defined(SOCKIO_USE_TICKETLOCK)
#include <odp/api/ticketlock.h>
#else
#include <odp/api/spinlock.h>
#endif

#define ODP_SOCKET_MAX_BURST 128
#define ODP_SOCKET_MAX_BACKLOG 16384

/**
 * Encapsulate a regular TCP/UDP socket
 */
typedef struct {
	int sockfd; /** Socket descriptor */
	odp_pool_t pool; /** buffer pool to allocate chuncks to */
	size_t buf_size; /** size of chunk to read from socket */
} sock_t;

typedef struct {
	int bytes_left;
	int buf_offset;
} pkt_ctx;

struct sockio_entry {
	/*Entry r/w locks because STREAM/DGRAM sockets are full duplex ?*/
	/*If needed, include them, otherwise it is early useless optimization */
#ifdef SOCKIO_USE_PTHREADLOCK
	odp_pthreadlock_t lock;
#elif defined(SOCKIO_USE_TICKETLOCK)
	odp_ticketlock_t lock;
#else
	odp_spinlock_t lock;
#endif
	int taken; /** is entry taken(1) or free(0) */
	odp_queue_t inq_default;
	odp_queue_t outq_default;
	odp_queue_t sndq_buffer; // socket sends may block, so buffer internally here
	odp_packet_t incomplete_buf;
	pkt_ctx snd_ctx;
	odp_sockio_type_t type;
	sock_t sfd; /** Using the socket API and kernel stack for IO */
	uint32_t epoll_events; /* Use this to control the events epoll wakes a sockio up for */
	odp_sockio_t sid;
	int index;
	odp_event_t cmd_ev; /* Event to use with epoll */
};

typedef union {
	struct sockio_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct sockio_entry))];
} sockio_entry_t;

int odp_sockio_sendpkt(odp_packet_t pkt, sockio_entry_t *sockio_entry);

/* Try to flush the send buffer to keep TCP happy
 * returns number of packets sent
 *         -1 when the buffer is blocked
 */
int odp_sockio_pushsend(sockio_entry_t *sockio_entry);

sockio_entry_t *get_sockio_entry(odp_sockio_t id);
odp_sockio_t get_sockio_id(sockio_entry_t *entry);

// Allow the scheduler to allow only some threads to do
// TCP/IP processing.
//int sockin_poll(sockio_entry_t *entry);
int sockin_poll(uint32_t sockio_idx);

// Do stream socket setup and create events to be passed
// to worker threads for creating new socket connections
// with the proper priority.
int listen_sockin_accept(odp_sockio_t sio, odp_event_t *evt_tbl, int num);
int _listen_sockin_accept(sockio_entry_t *entry, odp_event_t *evt_tbl, int num);
void odp_sockio_accept_free(odp_buffer_t c_ev);

#ifdef __cplusplus
}
#endif

#endif
