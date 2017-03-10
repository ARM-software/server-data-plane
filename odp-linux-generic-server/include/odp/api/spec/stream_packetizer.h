/* Copyright (c) 2017, ARM Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 * 
 * ODP Stream Packetizer
 */

/* First stab at making a "packetizer" interface for use with
 * L4 stream transports to break them into the L7 messages.
 */

#ifndef ODP_STREAM_PACKETIZER_H_
#define ODP_STREAM_PACKETIZER_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/socket_io.h>
#include <odp/api/pool.h>

/* typedef odp_packetizer_t */

/* A context class representing a packetizer for a binary protocol */
/* Assume that all data in pkt headers are in network order */
typedef struct {
    odp_pool_t pool; /* Buffer pool to place new packets in */
    uint32_t header_size; /* Size of the header--assumes we always start the buffer at a header field */
    uint32_t size_offset; /* Offset into the header that contains the overall size of payload */
    uint8_t num_bytes; /* Number of bytes to read as the size field */
} odp_packetizer_entry_t;

/* Create a simple packetizer, this is proof of concept, as a packetizer needs
 * to be a general unit as there are many L7 protocols out there. */
odp_packetizer_t odp_packetizer_create(odp_packetizer_entry_t packetizer);

int odp_packetizer_destroy(odp_packetizer_t handle);

/* Assign a packetizer to a sockio instance, so that any incoming buffer
 * is chopped up into the L7 packets it represents */
int odp_assign_packetizer_sockio(odp_sockio_t sockio,
                                 odp_packetizer_t packetizer,
                                 odp_pool_t pool);

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif
