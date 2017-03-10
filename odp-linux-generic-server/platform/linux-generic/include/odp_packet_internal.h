/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor - implementation internal
 */

#ifndef ODP_PACKET_INTERNAL_H_
#define ODP_PACKET_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp_crypto_internal.h>

#define PACKET_JUMBO_LEN	(9 * 1024)

/** Minimum segment length expected by packet_parse_common() */
#define PACKET_PARSE_SEG_LEN 96

/**
 * Packet input & protocol flags
 */
typedef union {
	/* All input flags */
	uint64_t all;

	struct {
		uint64_t parsed_l2:1; /**< L2 parsed */
		uint64_t parsed_all:1;/**< Parsing complete */
		uint64_t dst_queue:1; /**< Dst queue present */

		uint64_t flow_hash:1; /**< Flow hash present */
		uint64_t timestamp:1; /**< Timestamp present */

		uint64_t l2:1;        /**< known L2 protocol present */
		uint64_t l3:1;        /**< known L3 protocol present */
		uint64_t l4:1;        /**< known L4 protocol present */

		uint64_t eth:1;       /**< Ethernet */
		uint64_t eth_bcast:1; /**< Ethernet broadcast */
		uint64_t eth_mcast:1; /**< Ethernet multicast */
		uint64_t jumbo:1;     /**< Jumbo frame */
		uint64_t vlan:1;      /**< VLAN hdr found */
		uint64_t vlan_qinq:1; /**< Stacked VLAN found, QinQ */

		uint64_t snap:1;      /**< SNAP */
		uint64_t arp:1;       /**< ARP */

		uint64_t ipv4:1;      /**< IPv4 */
		uint64_t ipv6:1;      /**< IPv6 */
		uint64_t ip_bcast:1;  /**< IP broadcast */
		uint64_t ip_mcast:1;  /**< IP multicast */
		uint64_t ipfrag:1;    /**< IP fragment */
		uint64_t ipopt:1;     /**< IP optional headers */

		uint64_t ipsec:1;     /**< IPSec packet. Required by the
					   odp_packet_has_ipsec_set() func. */
		uint64_t ipsec_ah:1;  /**< IPSec authentication header */
		uint64_t ipsec_esp:1; /**< IPSec encapsulating security
					   payload */
		uint64_t udp:1;       /**< UDP */
		uint64_t tcp:1;       /**< TCP */
		uint64_t tcpopt:1;    /**< TCP options present */
		uint64_t sctp:1;      /**< SCTP */
		uint64_t icmp:1;      /**< ICMP */

		uint64_t color:2;     /**< Packet color for traffic mgmt */
		uint64_t nodrop:1;    /**< Drop eligibility status */
	};
} input_flags_t;

ODP_STATIC_ASSERT(sizeof(input_flags_t) == sizeof(uint64_t),
		  "INPUT_FLAGS_SIZE_ERROR");

/**
 * Packet error flags
 */
typedef union {
	/* All error flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each detected error */
		uint32_t app_error:1; /**< Error bit for application use */
		uint32_t frame_len:1; /**< Frame length error */
		uint32_t snap_len:1;  /**< Snap length error */
		uint32_t l2_chksum:1; /**< L2 checksum error, checks TBD */
		uint32_t ip_err:1;    /**< IP error,  checks TBD */
		uint32_t tcp_err:1;   /**< TCP error, checks TBD */
		uint32_t udp_err:1;   /**< UDP error, checks TBD */
	};
} error_flags_t;

ODP_STATIC_ASSERT(sizeof(error_flags_t) == sizeof(uint32_t),
		  "ERROR_FLAGS_SIZE_ERROR");

/**
 * Packet output flags
 */
typedef union {
	/* All output flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each output option */
		uint32_t l3_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l3_chksum:1;     /**< L3 chksum override */
		uint32_t l4_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l4_chksum:1;     /**< L4 chksum override  */

		int8_t shaper_len_adj;    /**< adjustment for traffic mgr */
	};
} output_flags_t;

ODP_STATIC_ASSERT(sizeof(output_flags_t) == sizeof(uint32_t),
		  "OUTPUT_FLAGS_SIZE_ERROR");

/**
 * Packet parser metadata
 */
typedef struct {
	input_flags_t  input_flags;
	error_flags_t  error_flags;
	output_flags_t output_flags;

	uint32_t l2_offset; /**< offset to L2 hdr, e.g. Eth */
	uint32_t l3_offset; /**< offset to L3 hdr, e.g. IPv4, IPv6 */
	uint32_t l4_offset; /**< offset to L4 hdr (TCP, UDP, SCTP, also ICMP) */

	uint32_t l3_len;    /**< Layer 3 length */
	uint32_t l4_len;    /**< Layer 4 length */

} packet_parser_t;

/**
 * Internal Packet header
 *
 * To optimize fast path performance this struct is not initialized to zero in
 * packet_init(). Because of this any new fields added must be reviewed for
 * initialization requirements.
 */
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	/* Following members are initialized by packet_init() */
	packet_parser_t p;

	uint32_t frame_len;
	uint32_t headroom;
	uint32_t tailroom;

	odp_pktio_t input;

	/* Members below are not initialized by packet_init() */
	odp_queue_t dst_queue;   /**< Classifier destination queue */

	uint32_t flow_hash;      /**< Flow hash value */
	odp_time_t timestamp;    /**< Timestamp value */

	odp_crypto_generic_op_result_t op_result;  /**< Result for crypto */
} odp_packet_hdr_t;

typedef struct odp_packet_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t))];
} odp_packet_hdr_stride;

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)odp_buf_to_hdr((odp_buffer_t)pkt);
}

static inline void copy_packet_parser_metadata(odp_packet_hdr_t *src_hdr,
					       odp_packet_hdr_t *dst_hdr)
{
	dst_hdr->p = src_hdr->p;
}

static inline void copy_packet_cls_metadata(odp_packet_hdr_t *src_hdr,
					    odp_packet_hdr_t *dst_hdr)
{
	dst_hdr->p = src_hdr->p;
	dst_hdr->dst_queue = src_hdr->dst_queue;
	dst_hdr->flow_hash = src_hdr->flow_hash;
	dst_hdr->timestamp = src_hdr->timestamp;
	dst_hdr->op_result = src_hdr->op_result;
}

static inline void *packet_map(odp_packet_hdr_t *pkt_hdr,
			       uint32_t offset, uint32_t *seglen)
{
	if (offset > pkt_hdr->frame_len)
		return NULL;

	return buffer_map(&pkt_hdr->buf_hdr,
			  pkt_hdr->headroom + offset, seglen,
			  pkt_hdr->headroom + pkt_hdr->frame_len);
}

static inline void push_head(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->headroom  -= len;
	pkt_hdr->frame_len += len;
}

static inline void pull_head(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->headroom  += len;
	pkt_hdr->frame_len -= len;
}

static inline int push_head_seg(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	uint32_t extrasegs =
		(len - pkt_hdr->headroom + pkt_hdr->buf_hdr.segsize - 1) /
		pkt_hdr->buf_hdr.segsize;

	if (pkt_hdr->buf_hdr.segcount + extrasegs > ODP_BUFFER_MAX_SEG ||
	    seg_alloc_head(&pkt_hdr->buf_hdr, extrasegs))
		return -1;

	pkt_hdr->headroom += extrasegs * pkt_hdr->buf_hdr.segsize;
	return 0;
}

static inline void pull_head_seg(odp_packet_hdr_t *pkt_hdr)
{
	uint32_t extrasegs = (pkt_hdr->headroom - 1) / pkt_hdr->buf_hdr.segsize;

	seg_free_head(&pkt_hdr->buf_hdr, extrasegs);
	pkt_hdr->headroom -= extrasegs * pkt_hdr->buf_hdr.segsize;
}

static inline void push_tail(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->tailroom  -= len;
	pkt_hdr->frame_len += len;
}

static inline int push_tail_seg(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	uint32_t extrasegs =
		(len - pkt_hdr->tailroom + pkt_hdr->buf_hdr.segsize - 1) /
		pkt_hdr->buf_hdr.segsize;

	if (pkt_hdr->buf_hdr.segcount + extrasegs > ODP_BUFFER_MAX_SEG ||
	    seg_alloc_tail(&pkt_hdr->buf_hdr, extrasegs))
		return -1;

	pkt_hdr->tailroom += extrasegs * pkt_hdr->buf_hdr.segsize;
	return 0;
}

static inline void pull_tail_seg(odp_packet_hdr_t *pkt_hdr)
{
	uint32_t extrasegs = pkt_hdr->tailroom / pkt_hdr->buf_hdr.segsize;

	seg_free_tail(&pkt_hdr->buf_hdr, extrasegs);
	pkt_hdr->tailroom -= extrasegs * pkt_hdr->buf_hdr.segsize;
}

static inline void pull_tail(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->tailroom  += len;
	pkt_hdr->frame_len -= len;
}

static inline uint32_t packet_len(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->frame_len;
}

static inline void packet_set_len(odp_packet_hdr_t *pkt_hdr, uint32_t len)
{
	pkt_hdr->frame_len = len;
}

static inline int packet_parse_l2_not_done(packet_parser_t *prs)
{
	return !prs->input_flags.parsed_l2;
}

static inline int packet_parse_not_complete(odp_packet_hdr_t *pkt_hdr)
{
	return !pkt_hdr->p.input_flags.parsed_all;
}

/* Forward declarations */
int _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt);

odp_packet_t packet_alloc(odp_pool_t pool_hdl, uint32_t len, int parse);

/* Fill in parser metadata for L2 */
void packet_parse_l2(packet_parser_t *prs, uint32_t frame_len);

/* Perform full packet parse */
int packet_parse_full(odp_packet_hdr_t *pkt_hdr);

/* Reset parser metadata for a new parse */
void packet_parse_reset(odp_packet_hdr_t *pkt_hdr);

/* Convert a packet handle to a buffer handle */
odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt);

/* Convert a buffer handle to a packet handle */
odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf);

static inline int packet_hdr_has_l2(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.l2;
}

static inline void packet_hdr_has_l2_set(odp_packet_hdr_t *pkt_hdr, int val)
{
	pkt_hdr->p.input_flags.l2 = val;
}

static inline int packet_hdr_has_eth(odp_packet_hdr_t *pkt_hdr)
{
	return pkt_hdr->p.input_flags.eth;
}

static inline void packet_set_ts(odp_packet_hdr_t *pkt_hdr, odp_time_t *ts)
{
	if (ts != NULL) {
		pkt_hdr->timestamp = *ts;
		pkt_hdr->p.input_flags.timestamp = 1;
	}
}

int packet_parse_common(packet_parser_t *pkt_hdr, const uint8_t *ptr,
			uint32_t pkt_len, uint32_t seg_len);

int _odp_cls_parse(odp_packet_hdr_t *pkt_hdr, const uint8_t *parseptr);

#ifdef __cplusplus
}
#endif

#endif
