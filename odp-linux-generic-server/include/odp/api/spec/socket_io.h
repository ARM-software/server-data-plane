/* Copyright (c) 2017, ARM Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Socket IO
 */

/* To facilitate integrating some of the parts of ODP into
 * general server applications, we need to support using a
 * networking stack as an input source for events.
 *
 */

#ifndef ODP_SOCKET_IO_H_
#define ODP_SOCKET_IO_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp/api/packet.h>
#include <odp/api/queue.h>

/** ODP socket IO handle */
/* typedef uint32_t odp_sockio_t; */

/** Invalid socket IO handle */
/* #define ODP_SOCKIO_INVALID 0 */

/** Connection event struct */
/*
 * struct {
 *	sock_t sfd;
 *	uint32_t peer_addr;
 *	uint32_t peer_port;
 *	uint32_t host_addr;
 *	uint32_t host_port;
 *	};
 */

/**
 * typedef enum {
 *	ODP_SOCKIO_TYPE_DATAGRAM = 0x1,
 *	ODP_SOCKIO_TYPE_STREAM = 0x2,
 *	ODP_SOCKIO_TYPE_STREAM_LISTEN = 0x3,
 * } odp_sockio_type_t;
 */

/**
 * Flags for odp_sockio_create_queues
 *
 * ODP_SOCKIO_CREATE_INQUEUE
 * ODP_SOCKIO_CREATE_OUTQUEUE
 * ODP_SOCKIO_CREATE_SENDBUF
 */

/**
 * Create a listening socket. Will be managed by
 * ODP and when the socket has connections pending,
 * an event will be created to be handled by the
 * application for setting up memory pools, priorities etc.
 *
 * @param port      Port to bind the socket to
 * @param interface NIC Interface to bind listening socket to
 *
 * @return ODP socket io handle or ODP_SOCKIO_INVALID on error
 */
odp_sockio_t odp_sockio_create_listener(int port, char* interface);

/**
 * Open a ODP socket IO instance
 *
 * @param sockfd   Listening socket/UDP socket
 * @param pool     Pool to use for storing "packetized" data from socket
 *
 * @return ODP socket io handle or ODP_SOCKIO_INVALID on error
 */
odp_sockio_t odp_sockio_open(uint32_t sockfd, odp_pool_t pool);

/**
 * Create queues from a non-listening socket descriptor
 *
 * @param sockfd  Socket that is connected or UDP
 * @param pool	  Pool to use for storing packets
 * @param flags   Flags to describe which queues need to be attached to socket
 *
 * @return ODP socket handle or ODP_SOCKIO_INVALID on error
 */
odp_sockio_t odp_sockio_create_queues(uint32_t sockfd, odp_pool_t pool,
				      odp_sockio_type_t type, uint32_t flags);

/**
 * Close an ODP socket IO instance
 *
 * @param id    ODP socket IO handle
 *
 * @return 0 on success or -1 on error
 */
int odp_sockio_close(odp_sockio_t id);

/**
 * Recv chunks from an ODP socket IO instance
 *
 * @param id            ODP socket IO handle
 * @param pkt_table[]   Storage for packets
 * @param len           Length of pkt_table
 *
 * @return Number of packets recieved or -1 on error
 *
 */
int odp_sockio_recv(odp_sockio_t id, odp_packet_t pkt_table[], unsigned len);

/*
 * Send packets
 *
 * @param id            ODP socket IO handle
 * @param pkt_table[]   Array of pkts to send
 * @param               len length of pkt_table[]
 *
 * @return Number of packets sent or -1 on error
 */
int odp_sockio_send(odp_sockio_t id, odp_packet_t pkt_table[], unsigned len);

/*
 * Set the default input queue to be associated with a sockio handle
 *
 * @param id    ODP socket io handle
 * @param queue ODP queue handle
 *
 * @return 0 on success or -1 on error
 */
int odp_sockio_inq_setdef(odp_sockio_t id, odp_queue_t queue);

/*
 * Get default input queue associated with a sockio handle
 *
 * @param id    ODP socket IO handle
 *
 * @return Default input queue set or ODP_QUEUE_INVALID
 */
odp_queue_t odp_sockio_inq_getdef(odp_sockio_t id);

/*
 * Remove default input queue (if set)
 *
 *
 *
 */
int odp_sockio_inq_remdef(odp_sockio_t id);

/*
 * Query default output queue
 * 
 *
 *
 */
odp_queue_t odp_sockio_outq_getdef(odp_sockio_t id);

/*
 * Store socket input handle into packet 
 * 
 *
 *
 */
void odp_sockio_set_input(odp_packet_t pkt, odp_sockio_t id);

/*
 * Get stored socket input handle from packet
 * 
 *
 *
 */
odp_sockio_t odp_sockio_get_input(odp_packet_t pkt);

/*
 * Allow the socket IO to be accessed
 *
 *
 */
int odp_socket_io_start(odp_sockio_t id);

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif
