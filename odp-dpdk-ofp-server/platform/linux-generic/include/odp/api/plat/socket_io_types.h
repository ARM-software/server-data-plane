/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Socket IO
 */

#ifndef ODP_SOCKET_IO_TYPES_H_
#define ODP_SOCKET_IO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

typedef ODP_HANDLE_T(odp_sockio_t);

typedef struct {
	int sfd;

	uint32_t peer_addr;
	uint32_t peer_port;
	uint32_t host_addr;
	uint32_t host_port;
} connect_evt;

/**
 * Socket IO types
 */
typedef enum {
	ODP_SOCKIO_TYPE_DATAGRAM = 0x1,
	ODP_SOCKIO_TYPE_STREAM = 0x2,
	ODP_SOCKIO_TYPE_STREAM_LISTEN = 0x3,
} odp_sockio_type_t;

/** @internal */
typedef struct odp_sockin_queue_t {
	odp_sockio_t sockio;
} odp_sockin_queue_t;

/** @internal */
typedef struct odp_sockout_queue_t {
	odp_sockio_t sockio;
} odp_sockout_queue_t;

#define ODP_SOCKIO_INVALID _odp_cast_scalar(odp_sockio_t, 0)

#define ODP_SOCKIO_CREATE_INQUEUE  0x0001
#define ODP_SOCKIO_CREATE_OUTQUEUE 0x0002
#define ODP_SOCKIO_CREATE_SENDBUF  0x0004
#define ODP_SOCKIO_CREATE_ALL_QUEUES (ODP_SOCKIO_CREATE_INQUEUE | ODP_SOCKIO_CREATE_OUTQUEUE | ODP_SOCKIO_CREATE_SENDBUF)

#ifdef __cplusplus
}
#endif
#endif
