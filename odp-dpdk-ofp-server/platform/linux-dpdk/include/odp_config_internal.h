/* Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CONFIG_INTERNAL_H_
#define ODP_CONFIG_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum number of pools
 */
#define ODP_CONFIG_POOLS 256

/*
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES 16384

/*
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 64

/**
 * Maximum number of socket IO resources
 */
#define ODP_CONFIG_SOCKIO_ENTRIES 2048

/**
 * Maximum number of Packetizer resources
 */
#define ODP_CONFIG_PACKETIZER_ENTRIES 1024

/**
 * Maximum size of L7 header allowed
 */
#define ODP_CONFIG_L7_HDR_SIZE 256

/**
 * Default size of packetizer input buffer
 */
#define ODP_CONFIG_L7_INPUT_SIZE 32768
#define ODP_CONFIG_FILEIO_QS 16

/*
 * Minimum buffer alignment
 *
 * This defines the minimum supported buffer alignment. Requests for values
 * below this will be rounded up to this value.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MIN 16

/*
 * Maximum buffer alignment
 *
 * This defines the maximum supported buffer alignment. Requests for values
 * above this will fail.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MAX (4 * 1024)

/*
 * Default packet headroom
 *
 * This defines the minimum number of headroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations may reserve a larger than minimum headroom
 * size e.g. due to HW or a protocol specific alignment requirement.
 *
 * @internal In linux-generic implementation:
 * The default value (66) allows a 1500-byte packet to be received into a single
 * segment with Ethernet offset alignment and room for some header expansion.
 */
#define ODP_CONFIG_PACKET_HEADROOM 128

/*
 * Default packet tailroom
 *
 * This defines the minimum number of tailroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations are free to add to this as desired
 * without restriction. Note that most implementations will automatically
 * consider any unused portion of the last segment of a packet as tailroom
 */
#define ODP_CONFIG_PACKET_TAILROOM 0

/*
 * Maximum number of segments per packet
 */
#define ODP_CONFIG_PACKET_MAX_SEGS 6

/*
 * Minimum packet segment length
 *
 * This defines the minimum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) will be rounded up into
 * this value.
 */
#define ODP_CONFIG_PACKET_SEG_LEN_MIN 1024

/*
 * Maximum packet segment length
 *
 * This defines the maximum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) must not be larger than
 * this.
 */
#define ODP_CONFIG_PACKET_SEG_LEN_MAX (64 * 1024)

/*
 * Maximum packet buffer length
 *
 * This defines the maximum number of bytes that can be stored into a packet
 * (maximum return value of odp_packet_buf_len(void)). Attempts to allocate
 * (including default head- and tailrooms) or extend packets to sizes larger
 * than this limit will fail.
 *
 * @internal In linux-generic implementation:
 * - The value MUST be an integral number of segments
 * - The value SHOULD be large enough to accommodate jumbo packets (9K)
 */
#define ODP_CONFIG_PACKET_BUF_LEN_MAX (ODP_CONFIG_PACKET_SEG_LEN_MIN * 9)

/* Maximum number of shared memory blocks.
 *
 * This the the number of separate SHM areas that can be reserved concurrently
 */
#define ODP_CONFIG_SHM_BLOCKS (ODP_CONFIG_POOLS + 48)

/** Define a max number of events to allow epoll to return */
#define ODP_MAX_EPOLL_EVENTS 1024
#define ODP_MIN_EPOLL_EVENTS 1
#define ODP_EPOLL_BLOCK -1
#define ODP_EPOLL_NOBLOCK 0

#ifdef __cplusplus
}
#endif

#endif
