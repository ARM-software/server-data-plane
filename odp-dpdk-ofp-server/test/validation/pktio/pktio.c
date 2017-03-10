/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp_api.h>
#include <odp_cunit_common.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>

#include <stdlib.h>
#include "pktio.h"

#define PKT_BUF_NUM            32
#define PKT_BUF_SIZE           (9 * 1024)
#define PKT_LEN_NORMAL         64
#define PKT_LEN_MAX            (PKT_BUF_SIZE - ODPH_ETHHDR_LEN - \
				ODPH_IPV4HDR_LEN - ODPH_UDPHDR_LEN)

#define USE_MTU                0
#define MAX_NUM_IFACES         2
#define TEST_SEQ_INVALID       ((uint32_t)~0)
#define TEST_SEQ_MAGIC         0x92749451
#define TX_BATCH_LEN           4
#define MAX_QUEUES             128

#define PKTIN_TS_INTERVAL      (50 * ODP_TIME_MSEC_IN_NS)
#define PKTIN_TS_MIN_RES       1000
#define PKTIN_TS_MAX_RES       10000000000
#define PKTIN_TS_CMP_RES       1

#undef DEBUG_STATS

/** interface names used for testing */
static const char *iface_name[MAX_NUM_IFACES];

/** number of interfaces being used (1=loopback, 2=pair) */
static int num_ifaces;

/** while testing real-world interfaces additional time may be
    needed for external network to enable link to pktio
    interface that just become up.*/
static bool wait_for_network;

/** local container for pktio attributes */
typedef struct {
	const char *name;
	odp_pktio_t id;
	odp_pktout_queue_t pktout;
	odp_queue_t queue_out;
	odp_queue_t inq;
	odp_pktin_mode_t in_mode;
} pktio_info_t;

/** magic number and sequence at start of UDP payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
	odp_u32be_t seq;
} pkt_head_t;

/** magic number at end of UDP payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
} pkt_tail_t;

/** Run mode */
typedef enum {
	PKT_POOL_UNSEGMENTED,
	PKT_POOL_SEGMENTED,
} pkt_segmented_e;

typedef enum {
	TXRX_MODE_SINGLE,
	TXRX_MODE_MULTI,
	TXRX_MODE_MULTI_EVENT
} txrx_mode_e;

typedef enum {
	RECV_TMO,
	RECV_MQ_TMO,
	RECV_MQ_TMO_NO_IDX,
} recv_tmo_mode_e;

/** size of transmitted packets */
static uint32_t packet_len = PKT_LEN_NORMAL;

/** default packet pool */
odp_pool_t default_pkt_pool = ODP_POOL_INVALID;

/** sequence number of IP packets */
odp_atomic_u32_t ip_seq;

/** Type of pool segmentation */
pkt_segmented_e pool_segmentation = PKT_POOL_UNSEGMENTED;

odp_pool_t pool[MAX_NUM_IFACES] = {ODP_POOL_INVALID, ODP_POOL_INVALID};

static inline void _pktio_wait_linkup(odp_pktio_t pktio)
{
	/* wait 1 second for link up */
	uint64_t wait_ns = (10 * ODP_TIME_MSEC_IN_NS);
	int wait_num = 100;
	int i;
	int ret = -1;

	for (i = 0; i < wait_num; i++) {
		ret = odp_pktio_link_status(pktio);
		if (ret < 0 || ret == 1)
			break;
		/* link is down, call status again after delay */
		odp_time_wait_ns(wait_ns);
	}

	if (ret != -1) {
		/* assert only if link state supported and
		 * it's down. */
		CU_ASSERT_FATAL(ret == 1);
	}
}

static void set_pool_len(odp_pool_param_t *params)
{
	switch (pool_segmentation) {
	case PKT_POOL_SEGMENTED:
		/* Force segment to minimum size */
		params->pkt.seg_len = 0;
		params->pkt.len = PKT_BUF_SIZE;
		break;
	case PKT_POOL_UNSEGMENTED:
	default:
		params->pkt.seg_len = PKT_BUF_SIZE;
		params->pkt.len = PKT_BUF_SIZE;
		break;
	}
}

static void pktio_pkt_set_macs(odp_packet_t pkt,
			       odp_pktio_t src, odp_pktio_t dst)
{
	uint32_t len;
	odph_ethhdr_t *eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, &len);
	int ret;

	ret = odp_pktio_mac_addr(src, &eth->src, ODP_PKTIO_MACADDR_MAXSIZE);
	CU_ASSERT(ret == ODPH_ETHADDR_LEN);
	CU_ASSERT(ret <= ODP_PKTIO_MACADDR_MAXSIZE);

	ret = odp_pktio_mac_addr(dst, &eth->dst, ODP_PKTIO_MACADDR_MAXSIZE);
	CU_ASSERT(ret == ODPH_ETHADDR_LEN);
	CU_ASSERT(ret <= ODP_PKTIO_MACADDR_MAXSIZE);
}

static uint32_t pktio_pkt_set_seq(odp_packet_t pkt)
{
	static uint32_t tstseq;
	size_t off;
	pkt_head_t head;
	pkt_tail_t tail;

	off = odp_packet_l4_offset(pkt);
	if (off == ODP_PACKET_OFFSET_INVALID) {
		CU_FAIL("packet L4 offset not set");
		return TEST_SEQ_INVALID;
	}

	head.magic = TEST_SEQ_MAGIC;
	head.seq   = tstseq;

	off += ODPH_UDPHDR_LEN;
	if (odp_packet_copy_from_mem(pkt, off, sizeof(head), &head) != 0)
		return TEST_SEQ_INVALID;

	tail.magic = TEST_SEQ_MAGIC;
	off = odp_packet_len(pkt) - sizeof(pkt_tail_t);
	if (odp_packet_copy_from_mem(pkt, off, sizeof(tail), &tail) != 0)
		return TEST_SEQ_INVALID;

	tstseq++;

	return head.seq;
}

static uint32_t pktio_pkt_seq(odp_packet_t pkt)
{
	size_t off;
	uint32_t seq = TEST_SEQ_INVALID;
	pkt_head_t head;
	pkt_tail_t tail;

	if (pkt == ODP_PACKET_INVALID) {
		fprintf(stderr, "error: pkt invalid\n");
		return TEST_SEQ_INVALID;
	}

	off = odp_packet_l4_offset(pkt);
	if (off ==  ODP_PACKET_OFFSET_INVALID) {
		fprintf(stderr, "error: offset invalid\n");
		return TEST_SEQ_INVALID;
	}

	off += ODPH_UDPHDR_LEN;
	if (odp_packet_copy_to_mem(pkt, off, sizeof(head), &head) != 0) {
		fprintf(stderr, "error: header copy failed\n");
		return TEST_SEQ_INVALID;
	}

	if (head.magic != TEST_SEQ_MAGIC) {
		fprintf(stderr, "error: header magic invalid %u\n", head.magic);
		return TEST_SEQ_INVALID;
	}

	if (odp_packet_len(pkt) == packet_len) {
		off = packet_len - sizeof(tail);
		if (odp_packet_copy_to_mem(pkt, off, sizeof(tail),
					   &tail) != 0) {
			fprintf(stderr, "error: header copy failed\n");
			return TEST_SEQ_INVALID;
		}

		if (tail.magic == TEST_SEQ_MAGIC) {
			seq = head.seq;
			CU_ASSERT(seq != TEST_SEQ_INVALID);
		} else {
			fprintf(stderr, "error: tail magic invalid %u\n",
				tail.magic);
		}
	} else {
		fprintf(stderr, "error: packet length invalid: %u (%u)\n",
			odp_packet_len(pkt), packet_len);
	}

	return seq;
}

static uint32_t pktio_init_packet(odp_packet_t pkt)
{
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	char *buf;
	uint16_t seq;
	uint8_t mac[ODP_PKTIO_MACADDR_MAXSIZE] = {0};
	int pkt_len = odp_packet_len(pkt);

	buf = odp_packet_data(pkt);

	/* Ethernet */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy(eth->src.addr, mac, ODPH_ETHADDR_LEN);
	memcpy(eth->dst.addr, mac, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* IP */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(0x0a000064);
	ip->src_addr = odp_cpu_to_be_32(0x0a000001);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(pkt_len - ODPH_ETHHDR_LEN);
	ip->ttl = 128;
	ip->proto = ODPH_IPPROTO_UDP;
	seq = odp_atomic_fetch_inc_u32(&ip_seq);
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);

	/* UDP */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = odp_cpu_to_be_16(12049);
	udp->dst_port = odp_cpu_to_be_16(12050);
	udp->length = odp_cpu_to_be_16(pkt_len -
				       ODPH_ETHHDR_LEN - ODPH_IPV4HDR_LEN);
	udp->chksum = 0;

	return pktio_pkt_set_seq(pkt);
}

static int pktio_fixup_checksums(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	uint32_t len;

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, &len);

	if (ip->proto != ODPH_IPPROTO_UDP) {
		CU_FAIL("unexpected L4 protocol");
		return -1;
	}

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, &len);

	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);
	udp->chksum = 0;
	udp->chksum = odph_ipv4_udp_chksum(pkt);

	return 0;
}

static int default_pool_create(void)
{
	odp_pool_param_t params;
	char pool_name[ODP_POOL_NAME_LEN];

	if (default_pkt_pool != ODP_POOL_INVALID)
		return -1;

	memset(&params, 0, sizeof(params));
	set_pool_len(&params);
	params.pkt.num     = PKT_BUF_NUM;
	params.type        = ODP_POOL_PACKET;

	snprintf(pool_name, sizeof(pool_name),
		 "pkt_pool_default_%d", pool_segmentation);
	default_pkt_pool = odp_pool_create(pool_name, &params);
	if (default_pkt_pool == ODP_POOL_INVALID)
		return -1;

	return 0;
}

static odp_pktio_t create_pktio(int iface_idx, odp_pktin_mode_t imode,
				odp_pktout_mode_t omode)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	const char *iface = iface_name[iface_idx];

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = imode;
	pktio_param.out_mode = omode;

	pktio = odp_pktio_open(iface, pool[iface_idx], &pktio_param);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
	CU_ASSERT(odp_pktio_to_u64(pktio) !=
		  odp_pktio_to_u64(ODP_PKTIO_INVALID));

	odp_pktin_queue_param_init(&pktin_param);

	/* Atomic queue when in scheduled mode */
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	/* By default, single input and output queue in all modes. Config can
	 * be overridden before starting the interface. */
	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);
	CU_ASSERT(odp_pktout_queue_config(pktio, NULL) == 0);

	if (wait_for_network)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS / 4);

	return pktio;
}

static int flush_input_queue(odp_pktio_t pktio, odp_pktin_mode_t imode)
{
	odp_event_t ev;
	odp_queue_t queue = ODP_QUEUE_INVALID;

	if (imode == ODP_PKTIN_MODE_QUEUE) {
		/* Assert breaks else-if without brackets */
		CU_ASSERT_FATAL(odp_pktin_event_queue(pktio, &queue, 1) == 1);
	} else if (imode == ODP_PKTIN_MODE_DIRECT) {
		return 0;
	}

	/* flush any pending events */
	while (1) {
		if (queue != ODP_QUEUE_INVALID)
			ev = odp_queue_deq(queue);
		else
			ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
		else
			break;
	}

	return 0;
}

static int create_packets(odp_packet_t pkt_tbl[], uint32_t pkt_seq[], int num,
			  odp_pktio_t pktio_src, odp_pktio_t pktio_dst)
{
	int i;

	for (i = 0; i < num; i++) {
		pkt_tbl[i] = odp_packet_alloc(default_pkt_pool, packet_len);
		if (pkt_tbl[i] == ODP_PACKET_INVALID)
			break;

		pkt_seq[i] = pktio_init_packet(pkt_tbl[i]);
		if (pkt_seq[i] == TEST_SEQ_INVALID) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}

		pktio_pkt_set_macs(pkt_tbl[i], pktio_src, pktio_dst);

		if (pktio_fixup_checksums(pkt_tbl[i]) != 0) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}
	}

	return i;
}

static int get_packets(pktio_info_t *pktio_rx, odp_packet_t pkt_tbl[],
		       int num, txrx_mode_e mode)
{
	odp_event_t evt_tbl[num];
	int num_evts = 0;
	int num_pkts = 0;
	int i;

	if (pktio_rx->in_mode == ODP_PKTIN_MODE_DIRECT) {
		odp_pktin_queue_t pktin;

		CU_ASSERT_FATAL(odp_pktin_queue(pktio_rx->id, &pktin, 1) == 1);
		return odp_pktin_recv(pktin, pkt_tbl, num);
	}

	if (mode == TXRX_MODE_MULTI) {
		if (pktio_rx->in_mode == ODP_PKTIN_MODE_QUEUE)
			num_evts = odp_queue_deq_multi(pktio_rx->inq, evt_tbl,
						       num);
		else
			num_evts = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
						      evt_tbl, num);
	} else {
		odp_event_t evt_tmp;

		if (pktio_rx->in_mode == ODP_PKTIN_MODE_QUEUE)
			evt_tmp = odp_queue_deq(pktio_rx->inq);
		else
			evt_tmp = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (evt_tmp != ODP_EVENT_INVALID)
			evt_tbl[num_evts++] = evt_tmp;
	}

	/* convert events to packets, discarding any non-packet events */
	for (i = 0; i < num_evts; ++i) {
		if (odp_event_type(evt_tbl[i]) == ODP_EVENT_PACKET)
			pkt_tbl[num_pkts++] = odp_packet_from_event(evt_tbl[i]);
		else
			odp_event_free(evt_tbl[i]);
	}

	return num_pkts;
}

static int wait_for_packets(pktio_info_t *pktio_rx, odp_packet_t pkt_tbl[],
			    uint32_t seq_tbl[], int num, txrx_mode_e mode,
			    uint64_t ns)
{
	odp_time_t wait_time, end;
	int num_rx = 0;
	int i;
	odp_packet_t pkt_tmp[num];

	wait_time = odp_time_local_from_ns(ns);
	end = odp_time_sum(odp_time_local(), wait_time);

	do {
		int n = get_packets(pktio_rx, pkt_tmp, num - num_rx, mode);

		if (n < 0)
			break;

		for (i = 0; i < n; ++i) {
			if (pktio_pkt_seq(pkt_tmp[i]) == seq_tbl[num_rx])
				pkt_tbl[num_rx++] = pkt_tmp[i];
			else
				odp_packet_free(pkt_tmp[i]);
		}
	} while (num_rx < num && odp_time_cmp(end, odp_time_local()) > 0);

	return num_rx;
}

static int recv_packets_tmo(odp_pktio_t pktio, odp_packet_t pkt_tbl[],
			    uint32_t seq_tbl[], int num, recv_tmo_mode_e mode,
			    uint64_t tmo, uint64_t ns)
{
	odp_packet_t pkt_tmp[num];
	odp_pktin_queue_t pktin[MAX_QUEUES];
	odp_time_t ts1, ts2;
	int num_rx = 0;
	int num_q;
	int i;
	int n;
	unsigned from_val;
	unsigned *from = NULL;

	if (mode == RECV_MQ_TMO)
		from = &from_val;

	num_q = odp_pktin_queue(pktio, pktin, MAX_QUEUES);
	CU_ASSERT_FATAL(num_q > 0);

	/** Multiple odp_pktin_recv_tmo()/odp_pktin_recv_mq_tmo() calls may be
	 *  required to discard possible non-test packets. */
	do {
		ts1 = odp_time_global();
		if (mode == RECV_TMO)
			n = odp_pktin_recv_tmo(pktin[0], pkt_tmp, num - num_rx,
					       tmo);
		else
			n = odp_pktin_recv_mq_tmo(pktin, (unsigned)num_q,
						  from, pkt_tmp,
						  num - num_rx, tmo);
		ts2 = odp_time_global();

		if (n <= 0)
			break;
		for (i = 0; i < n; i++) {
			if (pktio_pkt_seq(pkt_tmp[i]) == seq_tbl[num_rx])
				pkt_tbl[num_rx++] = pkt_tmp[i];
			else
				odp_packet_free(pkt_tmp[i]);
		}
		if (mode == RECV_MQ_TMO)
			CU_ASSERT(from_val < (unsigned)num_q);
	} while (num_rx < num);

	if (tmo == ODP_PKTIN_WAIT)
		CU_ASSERT(num_rx == num);
	if (num_rx < num)
		CU_ASSERT(odp_time_to_ns(odp_time_diff(ts2, ts1)) >=  ns);

	return num_rx;
}

static int send_packets(odp_pktout_queue_t pktout,
			odp_packet_t *pkt_tbl, unsigned pkts)
{
	int ret;
	unsigned sent = 0;

	while (sent < pkts) {
		ret = odp_pktout_send(pktout, &pkt_tbl[sent], pkts - sent);

		if (ret < 0) {
			CU_FAIL_FATAL("failed to send test packet");
			return -1;
		}

		sent += ret;
	}

	return 0;
}

static int send_packet_events(odp_queue_t queue,
			      odp_packet_t *pkt_tbl, unsigned pkts)
{
	int ret;
	unsigned i;
	unsigned sent = 0;
	odp_event_t ev_tbl[pkts];

	for (i = 0; i < pkts; i++)
		ev_tbl[i] = odp_packet_to_event(pkt_tbl[i]);

	while (sent < pkts) {
		ret = odp_queue_enq_multi(queue, &ev_tbl[sent], pkts - sent);

		if (ret < 0) {
			CU_FAIL_FATAL("failed to send test packet as events");
			return -1;
		}

		sent += ret;
	}

	return 0;
}

static void pktio_txrx_multi(pktio_info_t *pktio_a, pktio_info_t *pktio_b,
			     int num_pkts, txrx_mode_e mode)
{
	odp_packet_t tx_pkt[num_pkts];
	odp_packet_t rx_pkt[num_pkts];
	uint32_t tx_seq[num_pkts];
	int i, ret, num_rx;

	if (packet_len == USE_MTU) {
		uint32_t mtu;

		mtu = odp_pktio_mtu(pktio_a->id);
		if (odp_pktio_mtu(pktio_b->id) < mtu)
			mtu = odp_pktio_mtu(pktio_b->id);
		CU_ASSERT_FATAL(mtu > 0);
		packet_len = mtu;
		if (packet_len > PKT_LEN_MAX)
			packet_len = PKT_LEN_MAX;
	}

	/* generate test packets to send */
	ret = create_packets(tx_pkt, tx_seq, num_pkts, pktio_a->id,
			     pktio_b->id);
	if (ret != num_pkts) {
		CU_FAIL("failed to generate test packets");
		return;
	}

	/* send packet(s) out */
	if (mode == TXRX_MODE_SINGLE) {
		for (i = 0; i < num_pkts; ++i) {
			ret = odp_pktout_send(pktio_a->pktout, &tx_pkt[i], 1);
			if (ret != 1) {
				CU_FAIL_FATAL("failed to send test packet");
				odp_packet_free(tx_pkt[i]);
				return;
			}
		}
	} else if (mode == TXRX_MODE_MULTI) {
		send_packets(pktio_a->pktout, tx_pkt, num_pkts);
	} else {
		send_packet_events(pktio_a->queue_out, tx_pkt, num_pkts);
	}

	/* and wait for them to arrive back */
	num_rx = wait_for_packets(pktio_b, rx_pkt, tx_seq,
				  num_pkts, mode, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(num_rx == num_pkts);

	for (i = 0; i < num_rx; ++i) {
		CU_ASSERT_FATAL(rx_pkt[i] != ODP_PACKET_INVALID);
		CU_ASSERT(odp_packet_input(rx_pkt[i]) == pktio_b->id);
		CU_ASSERT(odp_packet_has_error(rx_pkt[i]) == 0);
		odp_packet_free(rx_pkt[i]);
	}
}

static void test_txrx(odp_pktin_mode_t in_mode, int num_pkts,
		      txrx_mode_e mode)
{
	int ret, i, if_b;
	pktio_info_t pktios[MAX_NUM_IFACES];
	pktio_info_t *io;

	/* create pktios and associate input/output queues */
	for (i = 0; i < num_ifaces; ++i) {
		odp_pktout_queue_t pktout;
		odp_queue_t queue;
		odp_pktout_mode_t out_mode = ODP_PKTOUT_MODE_DIRECT;

		if (mode == TXRX_MODE_MULTI_EVENT)
			out_mode = ODP_PKTOUT_MODE_QUEUE;

		io = &pktios[i];

		io->name = iface_name[i];
		io->id   = create_pktio(i, in_mode, out_mode);
		if (io->id == ODP_PKTIO_INVALID) {
			CU_FAIL("failed to open iface");
			return;
		}

		if (mode == TXRX_MODE_MULTI_EVENT) {
			CU_ASSERT_FATAL(odp_pktout_event_queue(io->id,
							       &queue, 1) == 1);
		} else {
			CU_ASSERT_FATAL(odp_pktout_queue(io->id,
							 &pktout, 1) == 1);
			io->pktout = pktout;
			queue = ODP_QUEUE_INVALID;
		}

		io->queue_out = queue;
		io->in_mode   = in_mode;

		if (in_mode == ODP_PKTIN_MODE_QUEUE) {
			CU_ASSERT_FATAL(odp_pktin_event_queue(io->id, &queue, 1)
					== 1);
			io->inq = queue;
		} else {
			io->inq = ODP_QUEUE_INVALID;
		}

		ret = odp_pktio_start(io->id);
		CU_ASSERT(ret == 0);

		_pktio_wait_linkup(io->id);
	}

	/* if we have two interfaces then send through one and receive on
	 * another but if there's only one assume it's a loopback */
	if_b = (num_ifaces == 1) ? 0 : 1;
	pktio_txrx_multi(&pktios[0], &pktios[if_b], num_pkts, mode);

	for (i = 0; i < num_ifaces; ++i) {
		ret = odp_pktio_stop(pktios[i].id);
		CU_ASSERT_FATAL(ret == 0);
		flush_input_queue(pktios[i].id, in_mode);
		ret = odp_pktio_close(pktios[i].id);
		CU_ASSERT(ret == 0);
	}
}

void pktio_test_plain_queue(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, 1, TXRX_MODE_SINGLE);
	test_txrx(ODP_PKTIN_MODE_QUEUE, TX_BATCH_LEN, TXRX_MODE_SINGLE);
}

void pktio_test_plain_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, TX_BATCH_LEN, TXRX_MODE_MULTI);
	test_txrx(ODP_PKTIN_MODE_QUEUE, 1, TXRX_MODE_MULTI);
}

void pktio_test_plain_multi_event(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, 1, TXRX_MODE_MULTI_EVENT);
	test_txrx(ODP_PKTIN_MODE_QUEUE, TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT);
}

void pktio_test_sched_queue(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, 1, TXRX_MODE_SINGLE);
	test_txrx(ODP_PKTIN_MODE_SCHED, TX_BATCH_LEN, TXRX_MODE_SINGLE);
}

void pktio_test_sched_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, TX_BATCH_LEN, TXRX_MODE_MULTI);
	test_txrx(ODP_PKTIN_MODE_SCHED, 1, TXRX_MODE_MULTI);
}

void pktio_test_sched_multi_event(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, 1, TXRX_MODE_MULTI_EVENT);
	test_txrx(ODP_PKTIN_MODE_SCHED, TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT);
}

void pktio_test_recv(void)
{
	test_txrx(ODP_PKTIN_MODE_DIRECT, 1, TXRX_MODE_SINGLE);
}

void pktio_test_recv_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_DIRECT, TX_BATCH_LEN, TXRX_MODE_MULTI);
}

void pktio_test_recv_multi_event(void)
{
	test_txrx(ODP_PKTIN_MODE_DIRECT, 1, TXRX_MODE_MULTI_EVENT);
	test_txrx(ODP_PKTIN_MODE_DIRECT, TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT);
}

void pktio_test_recv_queue(void)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES];
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t in_queue_param;
	odp_pktout_queue_param_t out_queue_param;
	odp_pktout_queue_t pktout_queue[MAX_QUEUES];
	odp_pktin_queue_t pktin_queue[MAX_QUEUES];
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t tmp_pkt[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	odp_time_t wait_time, end;
	int num_rx = 0;
	int num_queues;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_DIRECT,
					ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &capa) == 0);

		odp_pktin_queue_param_init(&in_queue_param);
		num_queues = capa.max_input_queues;
		in_queue_param.num_queues  = num_queues;
		in_queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
		in_queue_param.hash_proto.proto.ipv4_udp = 1;

		ret = odp_pktin_queue_config(pktio[i], &in_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		odp_pktout_queue_param_init(&out_queue_param);
		out_queue_param.num_queues  = capa.max_output_queues;

		ret = odp_pktout_queue_config(pktio[i], &out_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; ++i)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	if (num_ifaces > 1)
		pktio_rx = pktio[1];
	else
		pktio_rx = pktio_tx;

	/* Allocate and initialize test packets */
	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
			     pktio_rx);
	if (ret != TX_BATCH_LEN) {
		CU_FAIL("Failed to generate test packets");
		return;
	}

	/* Send packets */
	num_queues = odp_pktout_queue(pktio_tx, pktout_queue, MAX_QUEUES);
	CU_ASSERT_FATAL(num_queues > 0);
	if (num_queues > MAX_QUEUES)
		num_queues = MAX_QUEUES;

	ret = odp_pktout_send(pktout_queue[num_queues - 1], pkt_tbl,
			      TX_BATCH_LEN);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	/* Receive packets */
	num_queues = odp_pktin_queue(pktio_rx, pktin_queue, MAX_QUEUES);
	CU_ASSERT_FATAL(num_queues > 0);
	if (num_queues > MAX_QUEUES)
		num_queues = MAX_QUEUES;

	wait_time = odp_time_local_from_ns(ODP_TIME_SEC_IN_NS);
	end = odp_time_sum(odp_time_local(), wait_time);
	do {
		int n = 0;

		for (i = 0; i < num_queues; i++) {
			n = odp_pktin_recv(pktin_queue[i], tmp_pkt,
					   TX_BATCH_LEN);
			if (n != 0)
				break;
		}
		if (n < 0)
			break;
		for (i = 0; i < n; i++) {
			if (pktio_pkt_seq(tmp_pkt[i]) == pkt_seq[num_rx])
				pkt_tbl[num_rx++] = tmp_pkt[i];
			else
				odp_packet_free(tmp_pkt[i]);
		}
	} while (num_rx < TX_BATCH_LEN &&
		 odp_time_cmp(end, odp_time_local()) > 0);

	CU_ASSERT(num_rx == TX_BATCH_LEN);

	for (i = 0; i < num_rx; i++)
		odp_packet_free(pkt_tbl[i]);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void test_recv_tmo(recv_tmo_mode_e mode)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES];
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t in_queue_param;
	odp_pktout_queue_t pktout_queue;
	int test_pkt_count = 6;
	odp_packet_t pkt_tbl[test_pkt_count];
	uint32_t pkt_seq[test_pkt_count];
	uint64_t ns;
	unsigned num_q;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_DIRECT,
					ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &capa) == 0);

		odp_pktin_queue_param_init(&in_queue_param);
		if (mode == RECV_TMO)
			num_q = 1;
		else
			num_q = (capa.max_input_queues < MAX_QUEUES) ?
					capa.max_input_queues : MAX_QUEUES;
		in_queue_param.num_queues  = num_q;
		in_queue_param.hash_enable = (num_q > 1) ? 1 : 0;
		in_queue_param.hash_proto.proto.ipv4_udp = 1;

		ret = odp_pktin_queue_config(pktio[i], &in_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	memset(pkt_seq, 0, sizeof(pkt_seq));

	/* No packets sent yet, so should wait */
	ns = 100 * ODP_TIME_MSEC_IN_NS;
	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[0], &pkt_seq[0], 1, mode,
			       odp_pktin_wait_time(ns), ns);
	CU_ASSERT(ret == 0);

	ret = create_packets(pkt_tbl, pkt_seq, test_pkt_count, pktio_tx,
			     pktio_rx);
	CU_ASSERT_FATAL(ret == test_pkt_count);

	ret = odp_pktout_send(pktout_queue, pkt_tbl, test_pkt_count);
	CU_ASSERT_FATAL(ret == test_pkt_count);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[0], &pkt_seq[0], 1, mode,
			       ODP_PKTIN_WAIT, 0);
	CU_ASSERT_FATAL(ret == 1);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[1], &pkt_seq[1], 1, mode,
			       ODP_PKTIN_NO_WAIT, 0);
	CU_ASSERT_FATAL(ret == 1);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[2], &pkt_seq[2], 1, mode,
			       odp_pktin_wait_time(0), 0);
	CU_ASSERT_FATAL(ret == 1);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[3], &pkt_seq[3], 3, mode,
			       odp_pktin_wait_time(ns), ns);
	CU_ASSERT_FATAL(ret == 3);

	for (i = 0; i < test_pkt_count; i++)
		odp_packet_free(pkt_tbl[i]);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

void pktio_test_recv_tmo(void)
{
	test_recv_tmo(RECV_TMO);
}

void pktio_test_recv_mq_tmo(void)
{
	test_recv_tmo(RECV_MQ_TMO);
	test_recv_tmo(RECV_MQ_TMO_NO_IDX);
}

void pktio_test_recv_mtu(void)
{
	packet_len = USE_MTU;
	pktio_test_sched_multi();
	packet_len = PKT_LEN_NORMAL;
}

void pktio_test_mtu(void)
{
	int ret;
	uint32_t mtu;

	odp_pktio_t pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
					 ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	mtu = odp_pktio_mtu(pktio);
	CU_ASSERT(mtu > 0);

	printf(" %" PRIu32 " ",  mtu);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(ret == 0);
}

void pktio_test_promisc(void)
{
	int ret;
	odp_pktio_capability_t capa;

	odp_pktio_t pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
					 ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	ret = odp_pktio_promisc_mode(pktio);
	CU_ASSERT(ret >= 0);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0);
	if (!capa.set_op.op.promisc_mode) {
		printf("promiscuous mode not supported\n");
		ret = odp_pktio_close(pktio);
		CU_ASSERT(ret == 0);
		return;
	}

	ret = odp_pktio_promisc_mode_set(pktio, 1);
	CU_ASSERT(0 == ret);

	/* Verify that promisc mode set */
	ret = odp_pktio_promisc_mode(pktio);
	CU_ASSERT(1 == ret);

	ret = odp_pktio_promisc_mode_set(pktio, 0);
	CU_ASSERT(0 == ret);

	/* Verify that promisc mode is not set */
	ret = odp_pktio_promisc_mode(pktio);
	CU_ASSERT(0 == ret);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(ret == 0);
}

void pktio_test_mac(void)
{
	unsigned char mac_addr[ODP_PKTIO_MACADDR_MAXSIZE];
	int mac_len;
	int ret;
	odp_pktio_t pktio;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
			     ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	printf("testing mac for %s\n", iface_name[0]);

	mac_len = odp_pktio_mac_addr(pktio, mac_addr,
				     ODP_PKTIO_MACADDR_MAXSIZE);
	CU_ASSERT(ODPH_ETHADDR_LEN == mac_len);
	CU_ASSERT(ODP_PKTIO_MACADDR_MAXSIZE >= mac_len);

	printf(" %X:%X:%X:%X:%X:%X ",
	       mac_addr[0], mac_addr[1], mac_addr[2],
	       mac_addr[3], mac_addr[4], mac_addr[5]);

	/* Fail case: wrong addr_size. Expected <0. */
	mac_len = odp_pktio_mac_addr(pktio, mac_addr, 2);
	CU_ASSERT(mac_len < 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(0 == ret);
}

void pktio_test_open(void)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	int i;

	/* test the sequence open->close->open->close() */
	for (i = 0; i < 2; ++i) {
		pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
				     ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open("nothere", default_pkt_pool, &pktio_param);
	CU_ASSERT(pktio == ODP_PKTIO_INVALID);
}

void pktio_test_lookup(void)
{
	odp_pktio_t pktio, pktio_inval;
	odp_pktio_param_t pktio_param;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], default_pkt_pool, &pktio_param);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_lookup(iface_name[0]) == pktio);

	pktio_inval = odp_pktio_open(iface_name[0], default_pkt_pool,
				     &pktio_param);
	CU_ASSERT(odp_errno() != 0);
	CU_ASSERT(pktio_inval == ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_close(pktio) == 0);

	CU_ASSERT(odp_pktio_lookup(iface_name[0]) == ODP_PKTIO_INVALID);
}

void pktio_test_index(void)
{
	odp_pktio_t pktio, pktio_inval = ODP_PKTIO_INVALID;
	odp_pktio_param_t pktio_param;
	int ndx;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], default_pkt_pool, &pktio_param);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);

	ndx = odp_pktio_index(pktio);
	CU_ASSERT(ndx >= 0);
	CU_ASSERT(odp_pktio_index(pktio_inval) < 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
	CU_ASSERT(odp_pktio_index(pktio) < 0);
}

static void pktio_test_print(void)
{
	odp_pktio_t pktio;
	int i;

	for (i = 0; i < num_ifaces; ++i) {
		pktio = create_pktio(i, ODP_PKTIN_MODE_QUEUE,
				     ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

		/* Print pktio debug info and test that the
		 * odp_pktio_print() function is implemented. */
		odp_pktio_print(pktio);

		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}
}

void pktio_test_pktio_config(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	odp_pktio_config_init(&config);

	CU_ASSERT(odp_pktio_config(pktio, NULL) == 0);

	CU_ASSERT(odp_pktio_config(pktio, &config) == 0);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0);

	config = capa.config;
	CU_ASSERT(odp_pktio_config(pktio, &config) == 0);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
}

void pktio_test_info(void)
{
	odp_pktio_t pktio;
	odp_pktio_info_t pktio_info;
	int i;

	for (i = 0; i < num_ifaces; i++) {
		pktio = create_pktio(i, ODP_PKTIN_MODE_QUEUE,
				     ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_info(pktio, &pktio_info) == 0);

		printf("pktio %d\n  name   %s\n  driver %s\n", i,
		       pktio_info.name, pktio_info.drv_name);

		CU_ASSERT(strcmp(pktio_info.name, iface_name[i]) == 0);
		CU_ASSERT(pktio_info.pool == pool[i]);
		CU_ASSERT(pktio_info.param.in_mode == ODP_PKTIN_MODE_QUEUE);
		CU_ASSERT(pktio_info.param.out_mode == ODP_PKTOUT_MODE_DIRECT);

		CU_ASSERT(odp_pktio_info(ODP_PKTIO_INVALID, &pktio_info) < 0);

		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}
}

void pktio_test_pktin_queue_config_direct(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t queue_param;
	odp_pktin_queue_t pktin_queues[MAX_QUEUES];
	odp_queue_t in_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_capability(ODP_PKTIO_INVALID, &capa) < 0);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = capa.max_input_queues;

	odp_pktin_queue_param_init(&queue_param);

	queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
	queue_param.hash_proto.proto.ipv4_udp = 1;
	queue_param.num_queues  = num_queues;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_queue(pktio, pktin_queues, MAX_QUEUES)
		  == num_queues);
	CU_ASSERT(odp_pktin_event_queue(pktio, in_queues, MAX_QUEUES) < 0);

	queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	queue_param.num_queues  = 1;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_queue_config(ODP_PKTIO_INVALID, &queue_param) < 0);

	queue_param.num_queues = capa.max_input_queues + 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
}

void pktio_test_pktin_queue_config_sched(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t queue_param;
	odp_pktin_queue_t pktin_queues[MAX_QUEUES];
	odp_queue_t in_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = capa.max_input_queues;

	odp_pktin_queue_param_init(&queue_param);

	queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
	queue_param.hash_proto.proto.ipv4_udp = 1;
	queue_param.num_queues = num_queues;
	queue_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	queue_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_event_queue(pktio, in_queues, MAX_QUEUES)
		  == num_queues);
	CU_ASSERT(odp_pktin_queue(pktio, pktin_queues, MAX_QUEUES) < 0);

	queue_param.num_queues = 1;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	queue_param.num_queues = capa.max_input_queues + 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
}

void pktio_test_pktin_queue_config_queue(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t queue_param;
	odp_pktin_queue_t pktin_queues[MAX_QUEUES];
	odp_queue_t in_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_QUEUE, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = capa.max_input_queues;

	odp_pktin_queue_param_init(&queue_param);

	queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
	queue_param.hash_proto.proto.ipv4_udp = 1;
	queue_param.num_queues  = num_queues;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_event_queue(pktio, in_queues, MAX_QUEUES)
		  == num_queues);
	CU_ASSERT(odp_pktin_queue(pktio, pktin_queues, MAX_QUEUES) < 0);

	queue_param.num_queues = 1;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	queue_param.num_queues = capa.max_input_queues + 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

void pktio_test_pktout_queue_config(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktout_queue_param_t queue_param;
	odp_pktout_queue_t pktout_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_output_queues > 0);
	num_queues = capa.max_output_queues;

	odp_pktout_queue_param_init(&queue_param);

	queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	queue_param.num_queues  = num_queues;
	CU_ASSERT(odp_pktout_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktout_queue(pktio, pktout_queues, MAX_QUEUES)
		  == num_queues);

	queue_param.op_mode = ODP_PKTIO_OP_MT;
	queue_param.num_queues  = 1;
	CU_ASSERT(odp_pktout_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktout_queue_config(ODP_PKTIO_INVALID, &queue_param) < 0);

	queue_param.num_queues = capa.max_output_queues + 1;
	CU_ASSERT(odp_pktout_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

#ifdef DEBUG_STATS
static void _print_pktio_stats(odp_pktio_stats_t *s, const char *name)
{
	fprintf(stderr, "\n%s:\n"
		"  in_octets %" PRIu64 "\n"
		"  in_ucast_pkts %" PRIu64 "\n"
		"  in_discards %" PRIu64 "\n"
		"  in_errors %" PRIu64 "\n"
		"  in_unknown_protos %" PRIu64 "\n"
		"  out_octets %" PRIu64 "\n"
		"  out_ucast_pkts %" PRIu64 "\n"
		"  out_discards %" PRIu64 "\n"
		"  out_errors %" PRIu64 "\n",
		name,
		s->in_octets,
		s->in_ucast_pkts,
		s->in_discards,
		s->in_errors,
		s->in_unknown_protos,
		s->out_octets,
		s->out_ucast_pkts,
		s->out_discards,
		s->out_errors);
}
#endif

/* some pktio like netmap support various methods to
 * get statistics counters. ethtool strings are not standardised
 * and sysfs may not be supported. skip pktio_stats test until
 * we will solve that.*/
int pktio_check_statistics_counters(void)
{
	odp_pktio_t pktio;
	odp_pktio_stats_t stats;
	int ret;
	odp_pktio_param_t pktio_param;
	const char *iface = iface_name[0];

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface, pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_stats(pktio, &stats);
	(void)odp_pktio_close(pktio);

	if (ret == 0)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

void pktio_test_statistics_counters(void)
{
	odp_pktio_t pktio_rx, pktio_tx;
	odp_pktio_t pktio[MAX_NUM_IFACES];
	odp_packet_t pkt;
	odp_packet_t tx_pkt[1000];
	uint32_t pkt_seq[1000];
	odp_event_t ev;
	int i, pkts, tx_pkts, ret, alloc = 0;
	odp_pktout_queue_t pktout;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
	odp_pktio_stats_t stats[2];

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_DIRECT);

		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}
	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	CU_ASSERT(odp_pktout_queue(pktio_tx, &pktout, 1) == 1);

	ret = odp_pktio_start(pktio_tx);
	CU_ASSERT(ret == 0);
	if (num_ifaces > 1) {
		ret = odp_pktio_start(pktio_rx);
		CU_ASSERT(ret == 0);
	}

	/* flush packets with magic number in pipes */
	for (i = 0; i < 1000; i++) {
		ev = odp_schedule(NULL, wait);
		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
	}

	alloc = create_packets(tx_pkt, pkt_seq, 1000, pktio_tx, pktio_rx);

	ret = odp_pktio_stats_reset(pktio_tx);
	CU_ASSERT(ret == 0);
	if (num_ifaces > 1) {
		ret = odp_pktio_stats_reset(pktio_rx);
		CU_ASSERT(ret == 0);
	}

	/* send */
	for (pkts = 0; pkts != alloc; ) {
		ret = odp_pktout_send(pktout, &tx_pkt[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to send packet\n");
			break;
		}
		pkts += ret;
	}
	tx_pkts = pkts;

	/* get */
	for (i = 0, pkts = 0; i < 1000 && pkts != tx_pkts; i++) {
		ev = odp_schedule(NULL, wait);
		if (ev != ODP_EVENT_INVALID) {
			if (odp_event_type(ev) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev);
				if (pktio_pkt_seq(pkt) != TEST_SEQ_INVALID)
					pkts++;
			}
			odp_event_free(ev);
		}
	}

	CU_ASSERT(pkts == tx_pkts);

	ret = odp_pktio_stats(pktio_tx, &stats[0]);
	CU_ASSERT(ret == 0);

	if (num_ifaces > 1) {
		ret = odp_pktio_stats(pktio_rx, &stats[1]);
		CU_ASSERT(ret == 0);
		CU_ASSERT((stats[1].in_ucast_pkts == 0) ||
			  (stats[1].in_ucast_pkts >= (uint64_t)pkts));
		CU_ASSERT((stats[0].out_octets == 0) ||
			  (stats[0].out_octets >=
			  (PKT_LEN_NORMAL * (uint64_t)pkts)));
	} else {
		CU_ASSERT((stats[0].in_ucast_pkts == 0) ||
			  (stats[0].in_ucast_pkts == (uint64_t)pkts));
		CU_ASSERT((stats[0].in_octets == 0) ||
			  (stats[0].in_octets ==
			  (PKT_LEN_NORMAL * (uint64_t)pkts)));
	}

	CU_ASSERT(0 == stats[0].in_discards);
	CU_ASSERT(0 == stats[0].in_errors);
	CU_ASSERT(0 == stats[0].in_unknown_protos);
	CU_ASSERT(0 == stats[0].out_discards);
	CU_ASSERT(0 == stats[0].out_errors);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
#ifdef DEBUG_STATS
		_print_pktio_stats(&stats[i], iface_name[i]);
#endif
		flush_input_queue(pktio[i], ODP_PKTIN_MODE_SCHED);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}
}

void pktio_test_start_stop(void)
{
	odp_pktio_t pktio[MAX_NUM_IFACES];
	odp_pktio_t pktio_in;
	odp_packet_t pkt;
	odp_packet_t tx_pkt[1000];
	uint32_t pkt_seq[1000];
	odp_event_t ev;
	int i, pkts, ret, alloc = 0;
	odp_pktout_queue_t pktout;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}

	CU_ASSERT(odp_pktout_queue(pktio[0], &pktout, 1) == 1);

	/* Interfaces are stopped by default,
	 * Check that stop when stopped generates an error */
	ret = odp_pktio_stop(pktio[0]);
	CU_ASSERT(ret < 0);

	/* start first */
	ret = odp_pktio_start(pktio[0]);
	CU_ASSERT(ret == 0);
	/* Check that start when started generates an error */
	ret = odp_pktio_start(pktio[0]);
	CU_ASSERT(ret < 0);

	_pktio_wait_linkup(pktio[0]);

	/* Test Rx on a stopped interface. Only works if there are 2 */
	if (num_ifaces > 1) {

		alloc = create_packets(tx_pkt, pkt_seq, 1000, pktio[0],
				       pktio[1]);

		for (pkts = 0; pkts != alloc; ) {
			ret = odp_pktout_send(pktout, &tx_pkt[pkts],
					      alloc - pkts);
			if (ret < 0) {
				CU_FAIL("unable to enqueue packet\n");
				break;
			}
			pkts += ret;
		}
		/* check that packets did not arrive */
		for (i = 0, pkts = 0; i < 1000; i++) {
			ev = odp_schedule(NULL, wait);
			if (ev == ODP_EVENT_INVALID)
				continue;

			if (odp_event_type(ev) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev);
				if (pktio_pkt_seq(pkt) != TEST_SEQ_INVALID)
					pkts++;
			}
			odp_event_free(ev);
		}
		if (pkts)
			CU_FAIL("pktio stopped, received unexpected events");

		/* start both, send and get packets */
		/* 0 already started */
		ret = odp_pktio_start(pktio[1]);
		CU_ASSERT(ret == 0);

		_pktio_wait_linkup(pktio[1]);

		/* flush packets with magic number in pipes */
		for (i = 0; i < 1000; i++) {
			ev = odp_schedule(NULL, wait);
			if (ev != ODP_EVENT_INVALID)
				odp_event_free(ev);
		}
	}


	if (num_ifaces > 1)
		pktio_in = pktio[1];
	else
		pktio_in = pktio[0];

	alloc = create_packets(tx_pkt, pkt_seq, 1000, pktio[0], pktio_in);

	/* send */
	for (pkts = 0; pkts != alloc; ) {
		ret = odp_pktout_send(pktout, &tx_pkt[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to enqueue packet\n");
			break;
		}
		pkts += ret;
	}

	/* get */
	for (i = 0, pkts = 0; i < 1000; i++) {
		ev = odp_schedule(NULL, wait);
		if (ev != ODP_EVENT_INVALID) {
			if (odp_event_type(ev) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev);
				if (pktio_pkt_seq(pkt) != TEST_SEQ_INVALID)
					pkts++;
			}
			odp_event_free(ev);
		}
	}
	CU_ASSERT(pkts == alloc);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}

	/* Verify that a schedule call after stop and close does not generate
	   errors. */
	ev = odp_schedule(NULL, wait);
	CU_ASSERT(ev == ODP_EVENT_INVALID);
	if (ev != ODP_EVENT_INVALID)
		odp_event_free(ev);
}

/*
 * This is a pre-condition check that the pktio_test_send_failure()
 * test case can be run. If the TX interface MTU is larger that the
 * biggest packet we can allocate then the test won't be able to
 * attempt to send packets larger than the MTU, so skip the test.
 */
int pktio_check_send_failure(void)
{
	odp_pktio_t pktio_tx;
	uint32_t mtu;
	odp_pktio_param_t pktio_param;
	int iface_idx = 0;
	const char *iface = iface_name[iface_idx];
	odp_pool_capability_t pool_capa;

	if (odp_pool_capability(&pool_capa) < 0) {
		fprintf(stderr, "%s: pool capability failed\n", __func__);
		return ODP_TEST_INACTIVE;
	};

	memset(&pktio_param, 0, sizeof(pktio_param));

	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio_tx = odp_pktio_open(iface, pool[iface_idx], &pktio_param);
	if (pktio_tx == ODP_PKTIO_INVALID) {
		fprintf(stderr, "%s: failed to open pktio\n", __func__);
		return ODP_TEST_INACTIVE;
	}

	/* read the MTU from the transmit interface */
	mtu = odp_pktio_mtu(pktio_tx);

	odp_pktio_close(pktio_tx);

	if (mtu <= pool_capa.pkt.max_len - 32)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

void pktio_test_send_failure(void)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	int ret, i, alloc_pkts;
	uint32_t mtu;
	odp_pool_param_t pool_params;
	odp_pool_t pkt_pool;
	int long_pkt_idx = TX_BATCH_LEN / 2;
	pktio_info_t info_rx;
	odp_pktout_queue_t pktout;

	pktio_tx = create_pktio(0, ODP_PKTIN_MODE_DIRECT,
				ODP_PKTOUT_MODE_DIRECT);
	if (pktio_tx == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	CU_ASSERT_FATAL(odp_pktout_queue(pktio_tx, &pktout, 1) == 1);

	/* read the MTU from the transmit interface */
	mtu = odp_pktio_mtu(pktio_tx);

	ret = odp_pktio_start(pktio_tx);
	CU_ASSERT_FATAL(ret == 0);

	_pktio_wait_linkup(pktio_tx);

	/* configure the pool so that we can generate test packets larger
	 * than the interface MTU */
	memset(&pool_params, 0, sizeof(pool_params));
	pool_params.pkt.len     = mtu + 32;
	pool_params.pkt.seg_len = pool_params.pkt.len;
	pool_params.pkt.num     = TX_BATCH_LEN + 1;
	pool_params.type        = ODP_POOL_PACKET;
	pkt_pool = odp_pool_create("pkt_pool_oversize", &pool_params);
	CU_ASSERT_FATAL(pkt_pool != ODP_POOL_INVALID);

	if (num_ifaces > 1) {
		pktio_rx = create_pktio(1, ODP_PKTIN_MODE_DIRECT,
					ODP_PKTOUT_MODE_DIRECT);
		ret = odp_pktio_start(pktio_rx);
		CU_ASSERT_FATAL(ret == 0);

		_pktio_wait_linkup(pktio_rx);
	} else {
		pktio_rx = pktio_tx;
	}

	/* generate a batch of packets with a single overly long packet
	 * in the middle */
	for (i = 0; i < TX_BATCH_LEN; ++i) {
		uint32_t pkt_len;

		if (i == long_pkt_idx)
			pkt_len = pool_params.pkt.len;
		else
			pkt_len = PKT_LEN_NORMAL;

		pkt_tbl[i] = odp_packet_alloc(pkt_pool, pkt_len);
		if (pkt_tbl[i] == ODP_PACKET_INVALID)
			break;

		pkt_seq[i] = pktio_init_packet(pkt_tbl[i]);

		pktio_pkt_set_macs(pkt_tbl[i], pktio_tx, pktio_rx);
		if (pktio_fixup_checksums(pkt_tbl[i]) != 0) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}

		if (pkt_seq[i] == TEST_SEQ_INVALID) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}
	}
	alloc_pkts = i;

	if (alloc_pkts == TX_BATCH_LEN) {
		/* try to send the batch with the long packet in the middle,
		 * the initial short packets should be sent successfully */
		odp_errno_zero();
		ret = odp_pktout_send(pktout, pkt_tbl, TX_BATCH_LEN);
		CU_ASSERT_FATAL(ret == long_pkt_idx);
		CU_ASSERT(odp_errno() == 0);

		info_rx.id   = pktio_rx;
		info_rx.inq  = ODP_QUEUE_INVALID;
		info_rx.in_mode = ODP_PKTIN_MODE_DIRECT;

		i = wait_for_packets(&info_rx, pkt_tbl, pkt_seq, ret,
				     TXRX_MODE_MULTI, ODP_TIME_SEC_IN_NS);

		if (i == ret) {
			/* now try to send starting with the too-long packet
			 * and verify it fails */
			odp_errno_zero();
			ret = odp_pktout_send(pktout,
					      &pkt_tbl[long_pkt_idx],
					      TX_BATCH_LEN - long_pkt_idx);
			CU_ASSERT(ret == -1);
			CU_ASSERT(odp_errno() != 0);
		} else {
			CU_FAIL("failed to receive transmitted packets\n");
		}

		/* now reduce the size of the long packet and attempt to send
		 * again - should work this time */
		i = long_pkt_idx;
		odp_packet_pull_tail(pkt_tbl[i],
				     odp_packet_len(pkt_tbl[i]) -
				     PKT_LEN_NORMAL);
		pkt_seq[i] = pktio_init_packet(pkt_tbl[i]);

		pktio_pkt_set_macs(pkt_tbl[i], pktio_tx, pktio_rx);
		ret = pktio_fixup_checksums(pkt_tbl[i]);
		CU_ASSERT_FATAL(ret == 0);

		CU_ASSERT_FATAL(pkt_seq[i] != TEST_SEQ_INVALID);
		ret = odp_pktout_send(pktout, &pkt_tbl[i], TX_BATCH_LEN - i);
		CU_ASSERT_FATAL(ret == (TX_BATCH_LEN - i));

		i = wait_for_packets(&info_rx, &pkt_tbl[i], &pkt_seq[i], ret,
				     TXRX_MODE_MULTI, ODP_TIME_SEC_IN_NS);
		CU_ASSERT(i == ret);
	} else {
		CU_FAIL("failed to generate test packets\n");
	}

	for (i = 0; i < alloc_pkts; ++i) {
		if (pkt_tbl[i] != ODP_PACKET_INVALID)
			odp_packet_free(pkt_tbl[i]);
	}

	if (pktio_rx != pktio_tx) {
		CU_ASSERT(odp_pktio_stop(pktio_rx) == 0);
		CU_ASSERT(odp_pktio_close(pktio_rx) == 0);
	}
	CU_ASSERT(odp_pktio_stop(pktio_tx) == 0);
	CU_ASSERT(odp_pktio_close(pktio_tx) == 0);
	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
}

void pktio_test_recv_on_wonly(void)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktin_queue_t pktin;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DISABLED,
			     ODP_PKTOUT_MODE_DIRECT);

	if (pktio == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	CU_ASSERT(odp_pktin_queue(pktio, &pktin, 1) == 0);

	ret = odp_pktio_start(pktio);
	CU_ASSERT_FATAL(ret == 0);

	_pktio_wait_linkup(pktio);

	ret = odp_pktio_stop(pktio);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT_FATAL(ret == 0);
}

void pktio_test_send_on_ronly(void)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktout_queue_t pktout;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT,
			     ODP_PKTOUT_MODE_DISABLED);

	if (pktio == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	CU_ASSERT(odp_pktout_queue(pktio, &pktout, 1) == 0);

	ret = odp_pktio_start(pktio);
	CU_ASSERT_FATAL(ret == 0);

	_pktio_wait_linkup(pktio);

	ret = odp_pktio_stop(pktio);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT_FATAL(ret == 0);
}

int pktio_check_pktin_ts(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || !capa.config.pktin.bit.ts_all)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

void pktio_test_pktin_ts(void)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES];
	pktio_info_t pktio_rx_info;
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;
	odp_pktout_queue_t pktout_queue;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	uint64_t ns1, ns2;
	uint64_t res;
	odp_time_t ts_prev;
	odp_time_t ts;
	int num_rx = 0;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_DIRECT,
					ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &capa) == 0);
		CU_ASSERT_FATAL(capa.config.pktin.bit.ts_all);

		odp_pktio_config_init(&config);
		config.pktin.bit.ts_all = 1;
		CU_ASSERT_FATAL(odp_pktio_config(pktio[i], &config) == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	/* Test odp_pktin_ts_res() and odp_pktin_ts_from_ns() */
	res = odp_pktin_ts_res(pktio_tx);
	CU_ASSERT(res > PKTIN_TS_MIN_RES);
	CU_ASSERT(res < PKTIN_TS_MAX_RES);
	ns1 = 100;
	ts = odp_pktin_ts_from_ns(pktio_tx, ns1);
	ns2 = odp_time_to_ns(ts);
	/* Allow some arithmetic tolerance */
	CU_ASSERT((ns2 <= (ns1 + PKTIN_TS_CMP_RES)) &&
		  (ns2 >= (ns1 - PKTIN_TS_CMP_RES)));

	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
			     pktio_rx);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	/* Send packets one at a time and add delay between the packets */
	for (i = 0; i < TX_BATCH_LEN;  i++) {
		CU_ASSERT_FATAL(odp_pktout_send(pktout_queue,
						&pkt_tbl[i], 1) == 1);
		ret = wait_for_packets(&pktio_rx_info, &pkt_tbl[i], &pkt_seq[i],
				       1, TXRX_MODE_SINGLE, ODP_TIME_SEC_IN_NS);
		if (ret != 1)
			break;
		odp_time_wait_ns(PKTIN_TS_INTERVAL);
	}
	num_rx = i;
	CU_ASSERT(num_rx == TX_BATCH_LEN);

	ts_prev = ODP_TIME_NULL;
	for (i = 0; i < num_rx; i++) {
		ts = odp_packet_ts(pkt_tbl[i]);

		CU_ASSERT(odp_time_cmp(ts, ts_prev) > 0);

		ts_prev = ts;
		odp_packet_free(pkt_tbl[i]);
	}

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static int create_pool(const char *iface, int num)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_param_t params;

	memset(&params, 0, sizeof(params));
	set_pool_len(&params);
	params.pkt.num     = PKT_BUF_NUM;
	params.type        = ODP_POOL_PACKET;

	snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s_%d",
		 iface, pool_segmentation);

	pool[num] = odp_pool_create(pool_name, &params);
	if (ODP_POOL_INVALID == pool[num]) {
		fprintf(stderr, "%s: failed to create pool: %d",
			__func__, odp_errno());
		return -1;
	}

	return 0;
}

static int pktio_suite_init(void)
{
	int i;

	odp_atomic_init_u32(&ip_seq, 0);

	if (getenv("ODP_WAIT_FOR_NETWORK"))
		wait_for_network = true;

	iface_name[0] = getenv("ODP_PKTIO_IF0");
	iface_name[1] = getenv("ODP_PKTIO_IF1");
	num_ifaces = 1;

	if (!iface_name[0]) {
		printf("No interfaces specified, using default \"loop\".\n");
		iface_name[0] = "loop";
	} else if (!iface_name[1]) {
		printf("Using loopback interface: %s\n", iface_name[0]);
	} else {
		num_ifaces = 2;
		printf("Using paired interfaces: %s %s\n",
		       iface_name[0], iface_name[1]);
	}

	for (i = 0; i < num_ifaces; i++) {
		if (create_pool(iface_name[i], i) != 0)
			return -1;
	}

	if (default_pool_create() != 0) {
		fprintf(stderr, "error: failed to create default pool\n");
		return -1;
	}

	return 0;
}

int pktio_suite_init_unsegmented(void)
{
	pool_segmentation = PKT_POOL_UNSEGMENTED;
	return pktio_suite_init();
}

int pktio_suite_init_segmented(void)
{
	pool_segmentation = PKT_POOL_SEGMENTED;
	return pktio_suite_init();
}

int pktio_suite_term(void)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_t pool;
	int i;
	int ret = 0;

	for (i = 0; i < num_ifaces; ++i) {
		snprintf(pool_name, sizeof(pool_name),
			 "pkt_pool_%s_%d", iface_name[i], pool_segmentation);
		pool = odp_pool_lookup(pool_name);
		if (pool == ODP_POOL_INVALID)
			continue;

		if (odp_pool_destroy(pool) != 0) {
			fprintf(stderr, "error: failed to destroy pool %s\n",
				pool_name);
			ret = -1;
		}
	}

	if (odp_pool_destroy(default_pkt_pool) != 0) {
		fprintf(stderr, "error: failed to destroy default pool\n");
		ret = -1;
	}
	default_pkt_pool = ODP_POOL_INVALID;

	return ret;
}

odp_testinfo_t pktio_suite_unsegmented[] = {
	ODP_TEST_INFO(pktio_test_open),
	ODP_TEST_INFO(pktio_test_lookup),
	ODP_TEST_INFO(pktio_test_index),
	ODP_TEST_INFO(pktio_test_print),
	ODP_TEST_INFO(pktio_test_pktio_config),
	ODP_TEST_INFO(pktio_test_info),
	ODP_TEST_INFO(pktio_test_pktin_queue_config_direct),
	ODP_TEST_INFO(pktio_test_pktin_queue_config_sched),
	ODP_TEST_INFO(pktio_test_pktin_queue_config_queue),
	ODP_TEST_INFO(pktio_test_pktout_queue_config),
	ODP_TEST_INFO(pktio_test_plain_queue),
	ODP_TEST_INFO(pktio_test_plain_multi),
	ODP_TEST_INFO(pktio_test_sched_queue),
	ODP_TEST_INFO(pktio_test_sched_multi),
	ODP_TEST_INFO(pktio_test_recv),
	ODP_TEST_INFO(pktio_test_recv_multi),
	ODP_TEST_INFO(pktio_test_recv_queue),
	ODP_TEST_INFO(pktio_test_recv_tmo),
	ODP_TEST_INFO(pktio_test_recv_mq_tmo),
	ODP_TEST_INFO(pktio_test_recv_mtu),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_send_failure,
				  pktio_check_send_failure),
	ODP_TEST_INFO(pktio_test_mtu),
	ODP_TEST_INFO(pktio_test_promisc),
	ODP_TEST_INFO(pktio_test_mac),
	ODP_TEST_INFO(pktio_test_start_stop),
	ODP_TEST_INFO(pktio_test_recv_on_wonly),
	ODP_TEST_INFO(pktio_test_send_on_ronly),
	ODP_TEST_INFO(pktio_test_plain_multi_event),
	ODP_TEST_INFO(pktio_test_sched_multi_event),
	ODP_TEST_INFO(pktio_test_recv_multi_event),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_statistics_counters,
				  pktio_check_statistics_counters),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktin_ts,
				  pktio_check_pktin_ts),
	ODP_TEST_INFO_NULL
};

odp_testinfo_t pktio_suite_segmented[] = {
	ODP_TEST_INFO(pktio_test_plain_queue),
	ODP_TEST_INFO(pktio_test_plain_multi),
	ODP_TEST_INFO(pktio_test_sched_queue),
	ODP_TEST_INFO(pktio_test_sched_multi),
	ODP_TEST_INFO(pktio_test_recv),
	ODP_TEST_INFO(pktio_test_recv_multi),
	ODP_TEST_INFO(pktio_test_recv_mtu),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_send_failure,
				  pktio_check_send_failure),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t pktio_suites[] = {
	{"Packet I/O Unsegmented", pktio_suite_init_unsegmented,
	 pktio_suite_term, pktio_suite_unsegmented},
	{"Packet I/O Segmented", pktio_suite_init_segmented,
	 pktio_suite_term, pktio_suite_segmented},
	ODP_SUITE_INFO_NULL
};

int pktio_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(pktio_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
