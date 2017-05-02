/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* Implementation of socket io into ODP for general server use */

#include <odp/api/epoll.h>
#include <odp/api/debug.h>
#include <odp/api/packet.h>
#include <odp/api/shared_memory.h>
#include <odp/api/socket_io.h>
#include <odp/api/stream_packetizer.h>

#include <odp_pool_internal.h>
#include <odp_debug_internal.h>
#include <odp_internal.h>
#include <odp_packet_internal.h>
#include <odp_schedule_internal.h>
#include <odp_schedule_if.h>
#include <odp_socket_io_internal.h>
#include <odp_socket_io_queue.h>
#include <odp_stream_packetizer_internal.h>

#include "ofp.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>

typedef struct {
	sockio_entry_t entries[ODP_CONFIG_SOCKIO_ENTRIES];
} sockio_table_t;

static sockio_table_t *sockio_tbl;
static odp_pool_t connect_evt_pool;

static sockio_entry_t *get_entry(odp_sockio_t id)
{
	if (odp_unlikely(id == ODP_SOCKIO_INVALID ||
			 _odp_typeval(id) > ODP_CONFIG_SOCKIO_ENTRIES))
		return NULL;

	return &sockio_tbl->entries[_odp_typeval(id) - 1];
}

sockio_entry_t *get_sockio_entry(odp_sockio_t id)
{
	return get_entry(id);
}

static sockio_entry_t *get_sockio_by_index(uint32_t sockio_idx)
{
	return &sockio_tbl->entries[sockio_idx];
}

int odp_sockio_init_global(void)
{
	sockio_entry_t *sockio_entry;
	int id;
	odp_shm_t shm;
	odp_pool_t pool;
	odp_pool_param_t params;

	shm = odp_shm_reserve("odp_sockio_entries", sizeof(sockio_table_t),
			      sizeof(sockio_entry_t), 0);
	sockio_tbl = odp_shm_addr(shm);

	if (sockio_tbl == NULL)
		return -1;

	memset(sockio_tbl, 0, sizeof(sockio_table_t));

	for (id = 1; id <= ODP_CONFIG_SOCKIO_ENTRIES; ++id) {
		sockio_entry = get_entry(_odp_cast_scalar(odp_sockio_t, id));

#ifdef SOCKIO_USE_PTHREADLOCK
		odp_pthreadlock_init(&sockio_entry->s.lock);
#elif defined(SOCKIO_USE_TICKETLOCK)
		odp_ticketlock_init(&sockio_entry->s.lock);
#else
		odp_spinlock_init(&sockio_entry->s.lock);
#endif
		sockio_entry->s.sid = _odp_cast_scalar(odp_sockio_t, id);
	}

	// Allocate global pool for creating socket connection events
	connect_evt_pool = ODP_POOL_INVALID;
	odp_pool_param_init(&params);
	params.buf.size  = sizeof(connect_evt);
	params.buf.align = 0;
	params.buf.num	 = 1024; // Hard coded for now...
	params.type	 = ODP_POOL_BUFFER;

	pool = odp_pool_create("odp_connect_evt_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		ODP_ERR("Socket IO init: connect_evt pool create failed.\n");
		return -1;
	}

	connect_evt_pool = pool;

	return 0;
}

int odp_sockio_term_global(void)
{
	int id;
	for (id = 1; id <= ODP_CONFIG_SOCKIO_ENTRIES; ++id) {
		odp_sockio_close(_odp_cast_scalar(odp_sockio_t, id));
	}
	odp_pool_destroy(connect_evt_pool);
	return 0;
}

int odp_sockio_init_local(void)
{
	return 0;
}

static int is_free(sockio_entry_t *entry)
{
	return (entry->s.taken == 0);
}

static void set_free(sockio_entry_t *entry)
{
	entry->s.taken = 0;
}

static void set_taken(sockio_entry_t *entry)
{
	entry->s.taken = 1;
}

static void lock_entry(sockio_entry_t *entry)
{
#ifdef SOCKIO_USE_PTHREADLOCK
	odp_pthreadlock_lock(&entry->s.lock);
#elif defined(SOCKIO_USE_TICKETLOCK)
	odp_ticketlock_lock(&entry->s.lock);
#else
	odp_spinlock_lock(&entry->s.lock);
#endif
}

static void unlock_entry(sockio_entry_t *entry)
{
#ifdef SOCKIO_USE_PTHREADLOCK
	odp_pthreadlock_unlock(&entry->s.lock);
#elif defined(SOCKIO_USE_TICKETLOCK)
	odp_ticketlock_unlock(&entry->s.lock);
#else
	odp_spinlock_unlock(&entry->s.lock);
#endif
}

#if 0
static int trylock_entry(sockio_entry_t *entry)
{
#ifdef SOCKIO_USE_PTHREADLOCK
	return odp_pthreadlock_trylock(&entry->s.lock);
#elif defined(SOCKIO_USE_TICKETLOCK)
	return odp_ticketlock_trylock(&entry->s.lock);
#else
	return odp_spinlock_trylock(&entry->s.lock);
#endif
}
#endif

static void init_sockio_entry(sockio_entry_t *entry)
{
	set_taken(entry);
	entry->s.inq_default = ODP_QUEUE_INVALID;
	entry->s.outq_default = ODP_QUEUE_INVALID;
	//entry->s.epoll_events =
	//    EPOLLET | EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLONESHOT;
}

static odp_sockio_t alloc_lock_sockio_entry(void)
{
	sockio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_SOCKIO_ENTRIES; ++i) {
		entry = &sockio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry(entry);
			if (is_free(entry)) {
				init_sockio_entry(entry);
				entry->s.index = i;
				return entry->s.sid; /* return with entry locked! */
			}
			unlock_entry(entry);
		}
	}

	return ODP_SOCKIO_INVALID;
}

static int free_sockio_entry(odp_sockio_t id)
{
	sockio_entry_t *entry = get_entry(id);

	if (entry == NULL)
		return -1;

	set_free(entry);

	return 0;
}

// This funtion will mean different things for using the Linux
// network stack or if we are using a direct poll-mode access to
// the network card.
odp_sockio_t odp_sockio_create_listener(int port, char* interface UNUSED)
{
	int sfd;
	int nb = 1;
	struct ofp_sockaddr_in ai;

	//char port_buf[256];
	int error;
	//int flags = 1;
	odp_sockio_type_t type = ODP_SOCKIO_TYPE_STREAM_LISTEN;
	odp_sockio_t id = ODP_SOCKIO_INVALID;

	// Put port to some default value if it is not set
	if (port == -1) {
		port = 0;
	}

	// Set up the socket via OFP, not the kernel
	sfd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, OFP_IPPROTO_TCP);

	if (sfd < 0) {
		ODP_ERR("failed opening a listening ofp socket.\n");
		return ODP_SOCKIO_INVALID;
	}
	// Set non-blocking
	if (ofp_ioctl(sfd, OFP_FIONBIO, &nb)) {
		ODP_ERR("ofp_ioctl failed, err='%s'\n",
			ofp_strerror(ofp_errno));
	}

	memset(&ai, 0, sizeof(ai));
	ai.sin_family = OFP_AF_INET;
	ai.sin_port = odp_cpu_to_be_16(port);
	ai.sin_addr.s_addr = ofp_port_get_ipv4_addr(0, 0,
						    OFP_PORTCONF_IP_TYPE_IP_ADDR);
	ai.sin_len = sizeof(ai);

	error = ofp_bind(sfd, (struct ofp_sockaddr *)&ai,
			 sizeof(struct ofp_sockaddr));
	if (error < 0) {
		ODP_ERR("ofp_bind error on socket.\n");
		ofp_close(sfd);
		return ODP_SOCKIO_INVALID;
	}
	error = ofp_listen(sfd, ODP_SOCKET_MAX_BACKLOG);
	if (error != 0) {
		ofp_close(sfd);
		ODP_ERR("listen error on socket.\n");
		return ODP_SOCKIO_INVALID;
	}

	id = odp_sockio_create_queues(sfd, connect_evt_pool, type,
				      ODP_SOCKIO_CREATE_INQUEUE);

	// Let the socket be scheduled and start accepting connections
	if (id != ODP_SOCKIO_INVALID)
		odp_socket_io_start(id);

	return id;
}

odp_sockio_t odp_sockio_create_queues(uint32_t sockfd, odp_pool_t pool_hdl,
				      odp_sockio_type_t type, uint32_t flags)
{
	char name[ODP_QUEUE_NAME_LEN];
	queue_entry_t *queue_entry;
	pool_entry_t *pool_entry;
	odp_queue_t qid;
	odp_queue_t sid;
	odp_sockio_t id;

	sockio_entry_t *sockio_entry;
	id = alloc_lock_sockio_entry();
	if (id == ODP_SOCKIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_SOCKIO_INVALID;
	}
	/* if successful, alloc_sockio_entry() returns with the entry locked */

	sockio_entry = get_entry(id);
	sockio_entry->s.type = type;
	sockio_entry->s.sfd.sockfd = sockfd;
	sockio_entry->s.sfd.pool = pool_hdl;

	pool_entry = get_pool_entry(pool_handle_to_index(pool_hdl));

	odp_queue_param_t queue_param;
	sockio_entry->s.sfd.buf_size = pool_entry->s.params.buf.size;
	sockio_entry->s.outq_default = ODP_QUEUE_INVALID;
	sockio_entry->s.inq_default = ODP_QUEUE_INVALID;
	sockio_entry->s.sndq_buffer = ODP_QUEUE_INVALID;
	sockio_entry->s.incomplete_buf = ODP_PACKET_INVALID;
	sockio_entry->s.snd_ctx.bytes_left = 0;
	sockio_entry->s.snd_ctx.buf_offset = 0;

	/* Set up output queue attached to this socket */
	/* Create a default output queue for each pktio resource */
	if (flags & ODP_SOCKIO_CREATE_OUTQUEUE) {
		snprintf(name, sizeof(name), "%i-sockio_outq_default", _odp_typeval(id));
		name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		memset(&queue_param, 0, sizeof(odp_queue_param_t));
		queue_param.type = ODP_QUEUE_TYPE_PLAIN; // only make schedulable socket io queues
		qid = odp_queue_create(name, &queue_param);
		if (qid == ODP_QUEUE_INVALID) {
			close(sockfd);
			unlock_entry(sockio_entry);
			free_sockio_entry(id);
			ODP_ERR("Unable to init I/O type.\n");
			return ODP_SOCKIO_INVALID;
		}
		sockio_entry->s.outq_default = qid;

		queue_entry = queue_to_qentry(qid);
		queue_entry->s.sockout.sockio = id;

		ODP_DBG("Created out q: %d for socket: %d\n", qid, sockfd);

		/* Override queue defaults */
		queue_entry->s.enqueue = queue_ioout_enq;
		queue_entry->s.enqueue_multi = queue_ioout_enq_multi;
		queue_entry->s.dequeue = sockout_dequeue;
		queue_entry->s.dequeue_multi = sockout_deq_multi;
		/******************************************************/
	}

	/* Create input queue attached to this socket */
	if (flags & ODP_SOCKIO_CREATE_INQUEUE) {
		snprintf(name, sizeof(name), "%i-sockio_inq_default", _odp_typeval(id));
		name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		memset(&queue_param, 0, sizeof(odp_queue_param_t));
		queue_param.type = ODP_QUEUE_TYPE_SCHED;
		qid = odp_queue_create(name, &queue_param);
		if (qid == ODP_QUEUE_INVALID) {
			close(sockfd);
			unlock_entry(sockio_entry);
			free_sockio_entry(id);
			ODP_ERR("Unable to init I/O type.\n");
			return ODP_SOCKIO_INVALID;
		}

		sockio_entry->s.inq_default = qid;
		queue_entry = queue_to_qentry(qid);

		/* Override queue defaults */
		if (type == ODP_SOCKIO_TYPE_STREAM_LISTEN) {
			queue_entry->s.sockin.sockio = id;
			queue_entry->s.enqueue = listen_sockin_enqueue;
			queue_entry->s.enqueue_multi = listen_sockin_enq_multi;
			queue_entry->s.dequeue = listen_sockin_dequeue;
			queue_entry->s.dequeue_multi = listen_sockin_deq_multi;
		} else {
			queue_entry->s.sockin.sockio = id;
			queue_entry->s.enqueue = sockin_enqueue;
			queue_entry->s.enqueue_multi = sockin_enq_multi;
			queue_entry->s.dequeue = sockin_dequeue;
			queue_entry->s.dequeue_multi = sockin_deq_multi;
		}

		queue_entry->s.status = QUEUE_STATUS_NOTSCHED;
		ODP_DBG("Created in q: %d for socket: %d\n", qid, sockfd);
	}
	/*******************************************************/

	/* Create a send buffer to buffer non-send packets due
	 * to socket buffer congestion
	 */
	if (flags & ODP_SOCKIO_CREATE_SENDBUF) {
		snprintf(name, sizeof(name), "%i-pktio_sndq", _odp_typeval(id));
		name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		queue_param.type = ODP_QUEUE_TYPE_PLAIN;
		sid = odp_queue_create(name, &queue_param);
		if (sid == ODP_QUEUE_INVALID) {
			close(sockfd);
			unlock_entry(sockio_entry);
			free_sockio_entry(id);
			ODP_ERR("Unable to init I/O send buffer.\n");
			return ODP_SOCKIO_INVALID;
		}
		sockio_entry->s.sndq_buffer = sid;
	}
	/*********************************************************/

	sockio_entry->s.ss.sockfd = sockfd;
	sockio_entry->s.ss.event = 0;
	sockio_entry->s.ss.pkt = ODP_PACKET_INVALID;
	sockio_entry->s.ss.userdata = (uint64_t)(sockio_entry->s.index);
	sockio_entry->s.ev.ofp_sigev_notify = 1;
	sockio_entry->s.ev.ofp_sigev_notify_function = notify_sockio;
	sockio_entry->s.ev.ofp_sigev_value.sival_ptr = &(sockio_entry->s.ss);
	ofp_socket_sigevent(&(sockio_entry->s.ev));

	sched_fn->init_sockio(sockio_entry->s.index,
			      sockio_entry->s.sfd.sockfd);
			      //sockio_entry->s.epoll_events);
	unlock_entry(sockio_entry);
	return id;
}

odp_sockio_t odp_sockio_open(uint32_t sockfd, odp_pool_t pool_hdl)
{
	odp_sockio_type_t type = ODP_SOCKIO_TYPE_STREAM;
	int sfd;
	odp_sockio_t ret;
	int nb = 1;
	struct ofp_sockaddr_in caller;
	ofp_socklen_t alen = sizeof(caller);

	// Connect the input source or duplicate the UDP socket
	sfd = ofp_accept(sockfd, (struct ofp_sockaddr *)&caller, &alen);
	if (sfd < 0) {
#if 0
		switch (errno) {
		// we are UDP, duplicate the socket -- yes scaling will suck
		case EOPNOTSUPP:
			sfd = dup(sockfd);
			type = ODP_SOCKIO_TYPE_DATAGRAM;
			if (sfd < 0) {
				return ODP_SOCKIO_INVALID;
			}
			break;
		default:
			return ODP_SOCKIO_INVALID;
		}
#endif
		return ODP_SOCKIO_INVALID;
	}
	// Set non-blocking
	if (ofp_ioctl(sfd, OFP_FIONBIO, &nb)) {
		ODP_ERR("ofp_ioctl failed, err='%s'\n",
			ofp_strerror(ofp_errno));
	}

	ret =  odp_sockio_create_queues(sfd, pool_hdl, type,
					ODP_SOCKIO_CREATE_ALL_QUEUES);
	ofp_send_pending_pkt();
	return ret;
}

// Don't give socket to scheduler until we're ready -- ie, set up packetizers,
// classifiers...
int odp_socket_io_start(odp_sockio_t id)
{
	sockio_entry_t *sockio_entry;

	sockio_entry = get_entry(id);
	if (sockio_entry == NULL) {
		return -1;
	}

	// Guard this to avoid race with notify() from OFP
	lock_entry(sockio_entry);
	sockio_entry->s.started = 1;

	sched_fn->start_sockio(sockio_entry->s.index,
			       sockio_entry->s.sfd.sockfd);
			       //sockio_entry->s.epoll_events);
	unlock_entry(sockio_entry);

	return 0;
}

/* Must be called with lock held */
static int sockio_close(sockio_entry_t *entry)
{
	int res = -1;
	odp_event_t ev;
	odp_packet_t pkt;

	if (!is_free(entry)) {
		res = ofp_close(entry->s.sfd.sockfd);
		entry->s.sfd.sockfd = -1;
		odp_queue_destroy(entry->s.inq_default);
		odp_queue_destroy(entry->s.outq_default);
		entry->s.inq_default = ODP_QUEUE_INVALID;
		entry->s.outq_default = ODP_QUEUE_INVALID;

		// Clean up send q
		if (!odp_queue_is_empty(entry->s.sndq_buffer)) {
			ev = odp_queue_deq(entry->s.sndq_buffer);
			pkt = odp_packet_from_event(ev);
			while (pkt != ODP_PACKET_INVALID) {
				odp_packet_free(pkt);
				ev = odp_queue_deq(entry->s.sndq_buffer);
				pkt = odp_packet_from_event(ev);
			}
		}
		odp_queue_destroy(entry->s.sndq_buffer);
		entry->s.sndq_buffer = ODP_QUEUE_INVALID;

		// Clean up incomplete packet send
		if (entry->s.incomplete_buf != ODP_PACKET_INVALID) {
			odp_packet_free(entry->s.incomplete_buf);
		}
		entry->s.incomplete_buf = ODP_PACKET_INVALID;

		entry->s.snd_ctx.buf_offset = 0;
		entry->s.snd_ctx.bytes_left = 0;
		entry->s.started = 0;
		memset(&entry->s.ev, 0, sizeof(struct ofp_sigevent));
		memset(&entry->s.ss, 0, sizeof(struct ofp_sock_sigval));

		set_free(entry);
	}
	return res;
}

int odp_sockio_close(odp_sockio_t id)
{
	sockio_entry_t *entry;
	int res = -1;

	entry = get_entry(id);
	if (entry == NULL)
		return -1;

	lock_entry(entry);
	res = sockio_close(entry);
	unlock_entry(entry);

	if (res != 0)
		return -1;
	return 0;
}

void odp_sockio_set_input(odp_packet_t pkt, odp_sockio_t sockio)
{
	odp_packet_hdr(pkt)->input = _odp_cast_scalar(odp_pktio_t, sockio);
}

odp_sockio_t odp_sockio_get_input(odp_packet_t pkt)
{
	return _odp_cast_scalar(odp_sockio_t, odp_packet_hdr(pkt)->input);
}

odp_sockio_t get_sockio_id(sockio_entry_t *entry)
{
	return entry->s.sid;
}

// Here, we look at the sockio that this packet is going
// to.  Then we can reschedule the queue into the scheduler
void notify_sockio(union ofp_sigval sv)
{
	struct ofp_sock_sigval *ss = sv.sival_ptr;
	sockio_entry_t *sockio = get_sockio_by_index((uint64_t)ss->userdata);

	if (ss->sockfd != sockio->s.sfd.sockfd) {
		ODP_ERR("Getting notifies from phantom socket\n");
	}
        //assert(ss->sockfd == sockio->s.sfd.sockfd);

	// Always try to schedule this sockio when there are packets
	// incoming. The enqueue function in odp_schedule is locked to
	// make sure we do not
	if (sockio->s.started == 1) {
		sched_fn->start_sockio((uint64_t)ss->userdata, ss->sockfd);
	}
}

static int _sockio_recv(sockio_entry_t *sockio_entry, odp_packet_t pkt_table[], unsigned len)
{
	int pkts = 0;
	int i;
	odp_sockio_t id = get_sockio_id(sockio_entry);
	int sfd = sockio_entry->s.sfd.sockfd;
	int max_frame_len = sockio_entry->s.sfd.buf_size;
	odp_packet_t pkt = ODP_PACKET_INVALID;
	uint8_t *pkt_buf;
	int recv_bytes;
	odp_packetizer_t pktizer = odp_sockio_to_packetizer(id);
	int pktizer_pkts = 0;

	if (sockio_entry == NULL)
		return -1;
	if (sfd < 0)
		return -1;

	// Empty our send buffer if we have pending packets
	int ret = odp_sockio_pushsend(sockio_entry);
	if (ret < 0) {
		ODP_ERR("sfd %d hit error on pushsend()\n", sfd);
		return -1;
	}

	lock_entry(sockio_entry);
	// Loop through pkt table and recv data in chunks, not the
	// best method, but fits in with the opendataplane interface right now.
	for (pkts = 0; pkts < (int)len;) {
		if (pktizer != ODP_PACKETIZER_INVALID) {
			if (odp_packetizer_bufferlen(pktizer) ||
			    pkt != ODP_PACKET_INVALID) {
				pktizer_pkts = odp_run_packetizer(
				    pktizer, pkt, pkt_table + pkts, len - pkts);
				if (pktizer_pkts > 0) {
					pkts += pktizer_pkts;
				} else if (pktizer_pkts == -1) {
					// memory pressure being seen, stop here
					ODP_ERR("Pktizer has errored for socket %d!\n", sfd);
					break;
				}

				if (pkts == (int)len) {
					// we are done here
					break;
				} else if (pkts > (int)len) {
					ODP_ERR("Lost a packet in sock_recv");
					break;
				}
				// Packetizer takes ownership of packet
				pkt = ODP_PACKET_INVALID;
			}
		}

		if (odp_likely(pkt == ODP_PACKET_INVALID)) {
			pkt = odp_packet_alloc(sockio_entry->s.sfd.pool,
					       max_frame_len);
			if (odp_unlikely(pkt == ODP_PACKET_INVALID)) {
				ODP_ERR(
				    "Could not alloc a packet for socket %d!\n",
				    sfd);
				break;
			}
		}

		pkt_buf = odp_packet_data(pkt); // Get start of buffer, should
						// not be using
						// headroom/tailroom
		recv_bytes = ofp_recvfrom(sfd, pkt_buf, max_frame_len, OFP_MSG_DONTWAIT,
				      NULL, NULL);

		//ODP_ERR("Recieved %dB on sock %d\n", recv_bytes, sfd);
		/* No more data, break out of loop */
		if (odp_unlikely(recv_bytes <= 0)) {
			odp_packet_free(pkt);
// XXX: OFP is doing something not right when it does not have a packet to
// return, it sends back code 0, instead of -1.  Hack around it for now,
// connections never die.
#if 0
			if (ofp_errno != EAGAIN && ofp_errno != EWOULDBLOCK) {
				ODP_DBG("Closing sfd %d after peer reset "
					"connection\n",
					sfd);
				if (pktizer != ODP_PACKETIZER_INVALID) {
					odp_packetizer_destroy(pktizer);
				}
				sockio_close(sockio_entry);
				unlock_entry(sockio_entry);
				goto cleanup_sockio;
			}
#endif
			break;
		}
#if 0
		// Socket is closed, let scheduler know
		} else if (odp_unlikely(recv_bytes == 0) && pkts == 0) {
			odp_packet_free(pkt);
			if (pktizer != ODP_PACKETIZER_INVALID) {
				odp_packetizer_destroy(pktizer);
			}
			ODP_DBG("Closing sfd %d\n", sfd);
			sockio_close(sockio_entry);
			unlock_entry(sockio_entry);
			goto cleanup_sockio;
		}
#endif

		/* Set the length of our packet */
		packet_set_len(odp_packet_hdr(pkt), recv_bytes);
		if (pktizer == ODP_PACKETIZER_INVALID) {
			pkt_table[pkts] = pkt;
			pkt = ODP_PACKET_INVALID;
			pkts++;
		}
	}

	unlock_entry(sockio_entry);

	for (i = 0; i < pkts; ++i)
		odp_sockio_set_input(pkt_table[i], id);

	//printf("Return %d pkts socket %d\n", pkts, sfd);
	return pkts;
#if 0
cleanup_sockio:
	return -1;
#endif
}

int odp_sockio_recv(odp_sockio_t id, odp_packet_t pkt_table[], unsigned len)
{
	sockio_entry_t *sockio_entry = get_entry(id);
	return _sockio_recv(sockio_entry, pkt_table, len);
}

// Logic to send a single packet,
// Return 1 on success, return 0 on stall, return -1 on failure to send whole packet
int odp_sockio_sendpkt(odp_packet_t pkt, sockio_entry_t *sockio_entry)
{
	int sfd = sockio_entry->s.sfd.sockfd;
	uint32_t to_send = odp_packet_len(pkt);
	//odp_buffer_t buf = _odp_packet_to_buffer(pkt);
	//odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	unsigned flags = MSG_DONTWAIT;
	uint32_t seglen = 0;
	uint32_t cpylen;
	uint32_t curoff = 0;
	uint32_t offset = 0;
	uint32_t sent = 0;
	int ret = 0;
	uint8_t *mapaddr = NULL;

	// Invariant is we always complete sending a partially sent buffer
	if (sockio_entry->s.incomplete_buf != ODP_PACKET_INVALID)
		assert(pkt == sockio_entry->s.incomplete_buf);

	if (pkt == sockio_entry->s.incomplete_buf) {
		offset = sockio_entry->s.snd_ctx.buf_offset;
		to_send = sockio_entry->s.snd_ctx.bytes_left;
	}

	// Set curoff and the seg ptr
	curoff = offset;

	while (to_send) {
		mapaddr = (uint8_t*)odp_packet_offset(pkt, curoff, &seglen, NULL);
		cpylen = to_send > seglen ? seglen : to_send;
		sent = 0;
		while (sent < cpylen) {
			ret = ofp_send(sfd, mapaddr + sent, cpylen - sent, flags);
			if (ret > 0) {
				sent += ret;
			} else if (ret == 0) {
				ODP_ASSERT(0);
			} else if (ret < 0) {
				//if (ofp_errno != OFP_EAGAIN && ofp_errno != OFP_EWOULDBLOCK) {
				//	ODP_DBG("Closing sfd %d after peer "
				//		"reset connection (%d)\n",
				//		sfd, ofp_errno);
					/*if (pktizer != PACKETIZER_INVALID) {
						odp_packetizer_destroy(pktizer);
					}
					unlock_entry(sockio_entry);
					odp_sockio_close(id);*/
					//sockio_close(sockio_entry);
				//	goto closed_sockio;
				//} //else {
					//ODP_DBG("Incomplete packet sent on %d\n", sfd);
					sockio_entry->s.incomplete_buf = pkt;
					sockio_entry->s.snd_ctx.buf_offset =
					    offset + sent;
					sockio_entry->s.snd_ctx.bytes_left =
					    to_send - sent;
					//sockio_entry->s.epoll_events |=
					//    EPOLLOUT;
					// XXX: Try to reschedule the sockio queue
					ODP_DBG("ofp_send returned %d (%d), sent %d tosend %d\n",
						ret, ofp_errno,
						sockio_entry->s.snd_ctx.buf_offset,
						sockio_entry->s.snd_ctx.bytes_left);
					sched_fn->start_sockio(sockio_entry->s.index,
							       sockio_entry->s.sfd.sockfd);
					return 0;
				//}
			}
			//printf("Sent %dB(of %dB) on socket %d\n", sent, cpylen, sfd);
		}
		curoff += cpylen;
		offset += cpylen;
		to_send -= cpylen;
	}

	sockio_entry->s.incomplete_buf = ODP_PACKET_INVALID;
	sockio_entry->s.snd_ctx.buf_offset = 0;
	sockio_entry->s.snd_ctx.bytes_left = 0;
	//sockio_entry->s.epoll_events &=
	//    ~EPOLLOUT; // unset the wait for tx availability

	odp_packet_free(pkt);
	return 1;
//closed_sockio:
//	odp_packet_free(pkt);
//	return -1;
}

// Try to flush our buffer, have been seeing bugs where
// STREAM sockets will wedge
int odp_sockio_pushsend(sockio_entry_t *sockio_entry)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	int ret = 1;
	int pkts = 0;

	if (sockio_entry == NULL)
		return 0;

	lock_entry(sockio_entry);

	// Get the first packet, either an incomplete packet we must finish
	// sending or a new one.
	if (sockio_entry->s.incomplete_buf != ODP_PACKET_INVALID) {
		pkt = sockio_entry->s.incomplete_buf;
	} else {
		pkt = odp_packet_from_event(
		    odp_queue_deq(sockio_entry->s.sndq_buffer));
	}

	while (pkt != ODP_PACKET_INVALID && ret > 0) {
		//ODP_DBG("Push send\n");
		ret = odp_sockio_sendpkt(pkt, sockio_entry);
		if (ret > 0)
			pkts++;
		else
			break;
		pkt = odp_packet_from_event(
		    odp_queue_deq(sockio_entry->s.sndq_buffer));
	}
	unlock_entry(sockio_entry);

	ofp_send_pending_pkt();
	return (ret >= 0) ? pkts : -1;
}

int odp_sockio_send(odp_sockio_t id, odp_packet_t pkt_table[], unsigned len)
{
	sockio_entry_t *sockio_entry = get_entry(id);
	odp_event_t evt_table[QUEUE_MULTI_MAX];
	odp_packet_t pkt = ODP_PACKET_INVALID;
	int ret = 1;
	int pkts = 0;
	int i;

	if (sockio_entry == NULL)
		return -1;

	lock_entry(sockio_entry);

	if (len) {
		for (i = 0; i < (int)len; i++) {
			evt_table[i] = odp_packet_to_event(pkt_table[i]);
		}

		ret = odp_queue_enq_multi(sockio_entry->s.sndq_buffer,
					  evt_table, len);
		if (ret != (int)len) {
			ODP_ERR("Failed to enqueue onto send queue (%d out of "
				"%d)!\n",
				ret, (int)len);
			for (i = 0; i < (int)len; i++) {
				odp_packet_free(pkt_table[i]);
			}
			return -1;
		}
	}
	ret = 1;

	// Get the first packet, either an incomplete packet we must finish
	// sending or a new one.
	if (sockio_entry->s.incomplete_buf != ODP_PACKET_INVALID) {
		pkt = sockio_entry->s.incomplete_buf;
	} else {
		pkt = odp_packet_from_event(
		    odp_queue_deq(sockio_entry->s.sndq_buffer));
	}

	while (pkt != ODP_PACKET_INVALID && ret > 0) {
		ret = odp_sockio_sendpkt(pkt, sockio_entry);
		if (ret > 0)
			pkts++;
		else
			break; // Couldn't send, need to wait.
		pkt = odp_packet_from_event(
		    odp_queue_deq(sockio_entry->s.sndq_buffer));
	}

	// printf("sockio send sent %d pkts socket %d\n", pkts,
	// sockio_entry->s.sfd.sockfd);
	unlock_entry(sockio_entry);

	return pkts;
}

// Call sockio_recv and place packets into the input queues
// for dequeuing by worker threads in the scheduler (or polling...)
int sockin_poll(uint32_t sockio_idx)
{
	sockio_entry_t *entry = get_sockio_by_index(sockio_idx);
	odp_packet_t pkt_tbl[ODP_SOCKET_MAX_BURST];
	odp_event_t evt_tbl[ODP_SOCKET_MAX_BURST];
	odp_buffer_hdr_t *tmp_hdr_tbl[ODP_SOCKET_MAX_BURST];
	queue_entry_t *qentry;
	odp_buffer_t buf;
	int pkts = 0;
        int evts = 0;
	int i;

	switch (entry->s.type) {
	case ODP_SOCKIO_TYPE_DATAGRAM:
	case ODP_SOCKIO_TYPE_STREAM:
		qentry = queue_to_qentry(entry->s.inq_default);

		// Just get the number of pkts requested, no more for right now.
		pkts = _sockio_recv(entry, pkt_tbl, ODP_SOCKET_MAX_BURST); // QUEUE_MULTI_MAX);
		//ODP_DBG("Recieved %d packets\n", pkts);
		if (pkts > 0) {
			for (i = 0; i < pkts; ++i) {
				buf = _odp_packet_to_buffer(pkt_tbl[i]);
				tmp_hdr_tbl[i] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, pkts, 0);
		}

		if (pkts == -1) {
			return -1;
		}
		break;
	case ODP_SOCKIO_TYPE_STREAM_LISTEN:
		qentry = queue_to_qentry(entry->s.inq_default);

		evts = _listen_sockin_accept(entry, evt_tbl, ODP_SOCKET_MAX_BURST);

		if (evts > 0) {
			for (i = 0; i < evts; ++i) {
				buf = odp_buffer_from_event(evt_tbl[i]);
				tmp_hdr_tbl[i] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, evts, 0);
		}
		if (evts == -1) {
			return -1;
		}
		break;
	default:
		ODP_ERR("Invalid sockio type: %d\n", _odp_pri(entry->s.type));
		break;
	}
	return pkts;
}

// Connect sockets and create events for them to placed on queues.
// Returns number of connections created.
int _listen_sockin_accept(sockio_entry_t *entry, odp_event_t *evt_tbl, int num)
{
	int sfd;
	int num_conns = 0;
	connect_evt *c_ev;
	odp_buffer_t buf;
	struct sockaddr_in addr;
	uint32_t len;

	lock_entry(entry);
	for (int i = 0; i < num; i++) {

		sfd = ofp_accept(entry->s.sfd.sockfd, NULL, NULL);
		if (sfd < 0) {
			break;
		} else {
			buf = odp_buffer_alloc(connect_evt_pool);
			if (buf == ODP_BUFFER_INVALID) {
				ODP_ERR("Error allocating buffer for connection event.\n");
				return num_conns; 
			}
			c_ev = odp_buffer_addr(buf);
			c_ev->sfd = sfd;

			// Get peer address and host addresses, store in buffer
			getsockname(sfd, (struct sockaddr*)(&addr), &len);
			c_ev->host_addr = ntohs(addr.sin_addr.s_addr);
			c_ev->host_port = ntohs(addr.sin_port);

			getpeername(sfd, (struct sockaddr*)(&addr), &len);
			c_ev->peer_addr = ntohs(addr.sin_addr.s_addr);
			c_ev->peer_port = ntohs(addr.sin_port);
			_odp_buffer_event_type_set(buf, ODP_EVENT_SOCKET_CONNECT);

			evt_tbl[i] = odp_buffer_to_event(buf);
		}
		num_conns++;
	}

	unlock_entry(entry);
	ofp_send_pending_pkt();
	return num_conns;
}

void odp_sockio_accept_free(odp_buffer_t c_ev)
{
	_odp_buffer_event_type_set(c_ev, ODP_EVENT_BUFFER);
	odp_buffer_free(c_ev);
}

// Wrapper function for working with odp_sockio_t
int listen_sockin_accept(odp_sockio_t sio, odp_event_t *evt_tbl, int num)
{
	sockio_entry_t *sockio_entry = get_entry(sio);
	return _listen_sockin_accept(sockio_entry, evt_tbl, num);
}

odp_queue_t odp_sockio_inq_getdef(odp_sockio_t id)
{
	sockio_entry_t *sockio_entry = get_entry(id);

	if (sockio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return sockio_entry->s.inq_default;
}

odp_queue_t sockio_inq_getdef_by_index(int sock_idx)
{
	return sockio_tbl->entries[sock_idx].s.inq_default;
}

odp_queue_t odp_sockio_outq_getdef(odp_sockio_t id)
{
	sockio_entry_t *sockio_entry = get_entry(id);

	if (sockio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return sockio_entry->s.outq_default;
}

int sockout_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = _odp_packet_from_buffer(buf_hdr->handle.handle);
	int len = 1;
	int nbr;

	nbr = odp_sockio_send(qentry->s.sockout.sockio, &pkt, len);
	ofp_send_pending_pkt();
	return (nbr >= 0 ? 0 : -1);
}

odp_buffer_hdr_t *sockout_dequeue(queue_entry_t *qentry ODP_UNUSED)
{
	ODP_ABORT("attempted dequeue from a sockout queue");
	return NULL;
}

int sockout_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		      int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr;
	int i;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = _odp_packet_from_buffer(buf_hdr[i]->handle.handle);

	nbr = odp_sockio_send(qentry->s.sockout.sockio, pkt_tbl, num);
	ofp_send_pending_pkt();
	return (nbr >= 0 ? nbr : -1);
}

int sockout_deq_multi(queue_entry_t *qentry ODP_UNUSED,
		      odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
		      int num ODP_UNUSED)
{
	ODP_ABORT("attempted dequeue from a sockout queue");
	return 0;
}

int sockin_enqueue(queue_entry_t *qentry ODP_UNUSED,
		   odp_buffer_hdr_t *buf_hdr ODP_UNUSED,
		   int sustain ODP_UNUSED)
{
	ODP_ABORT("attempted enqueue to a sockin queue");
	return -1;
}

odp_buffer_hdr_t *sockin_dequeue(queue_entry_t *qentry)
{
	odp_buffer_hdr_t *buf_hdr;

	buf_hdr = queue_deq(qentry);

	if (buf_hdr == NULL) {
		odp_packet_t pkt;
		odp_buffer_t buf;
		odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
		odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
		int pkts, i, j;

		pkts = odp_sockio_recv(qentry->s.sockin.sockio, pkt_tbl,
				       QUEUE_MULTI_MAX);

		if (pkts > 0) {
			pkt = pkt_tbl[0];
			buf = _odp_packet_to_buffer(pkt);
			buf_hdr = odp_buf_to_hdr(buf);

			for (i = 1, j = 0; i < pkts; ++i) {
				buf = _odp_packet_to_buffer(pkt_tbl[i]);
				tmp_hdr_tbl[j++] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, j, 0);
		}
	}

	return buf_hdr;
}

int sockin_enq_multi(queue_entry_t *qentry ODP_UNUSED,
		     odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
		     int num ODP_UNUSED, int sustain ODP_UNUSED)
{
	ODP_ABORT("attempted enqueue to a sockin queue");
	return 0;
}

int sockin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		     int num)
{
	int nbr;

	nbr = queue_deq_multi(qentry, buf_hdr, num);

	if (nbr < num) {
		odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
		odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
		odp_buffer_t buf;
		int pkts, i;

		// Just get the number of pkts requested, no more for right now.
		pkts = odp_sockio_recv(
		    qentry->s.sockin.sockio, pkt_tbl,
		    num); // QUEUE_MULTI_MAX);
		if (pkts > 0) {
			for (i = 0; i < pkts; ++i) {
				buf = _odp_packet_to_buffer(pkt_tbl[i]);
				tmp_hdr_tbl[i] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, pkts, 0);
		}

		if (pkts == -1 && nbr == 0) {
			return -1;
		}

		// Try and dequeue some more instead of waiting for another
		// loop around the scheduler.
		pkts = queue_deq_multi(qentry, buf_hdr + nbr, num - nbr);
		nbr += pkts;
	}

	return nbr;
}

int listen_sockin_enqueue(queue_entry_t *queue ODP_UNUSED,
			  odp_buffer_hdr_t *buf_hdr ODP_UNUSED,
			  int sustain ODP_UNUSED)
{
	ODP_ABORT("attempted enqueue to a sockin queue");
	return -1;
}

odp_buffer_hdr_t *listen_sockin_dequeue(queue_entry_t *qentry)
{
	odp_buffer_hdr_t *buf_hdr;

	buf_hdr = queue_deq(qentry);

	if (buf_hdr == NULL) {
		odp_event_t evt;
		odp_buffer_t buf;
		odp_event_t evt_tbl[QUEUE_MULTI_MAX];
		odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
		int evts, i, j;

		evts = listen_sockin_accept(qentry->s.sockin.sockio, evt_tbl,
					     QUEUE_MULTI_MAX);

		if (evts > 0) {
			evt = evt_tbl[0];
			buf = (odp_buffer_t)evt;
			buf_hdr = odp_buf_to_hdr(buf);

			for (i = 1, j = 0; i < evts; ++i) {
				buf = odp_buffer_from_event(evt_tbl[i]);
				tmp_hdr_tbl[j++] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, j, 0);
		}
	}

	return buf_hdr;
}

int listen_sockin_enq_multi(queue_entry_t *queue ODP_UNUSED,
			    odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
			    int num ODP_UNUSED, int sustain ODP_UNUSED)
{
	ODP_ABORT("attempted enqueue to a listen sockin queue");
	return 0;
}

// TODO: Many of these socket functions could probably be combined into more generic
// functions
int listen_sockin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	int nbr;

	nbr = queue_deq_multi(qentry, buf_hdr, num);

	if (nbr < num) {
		odp_event_t evt_tbl[QUEUE_MULTI_MAX];
		odp_buffer_hdr_t *tmp_hdr_tbl[QUEUE_MULTI_MAX];
		odp_buffer_t buf;
		int evts, i;

		// Just get the number of pkts requested, no more for right now.
		evts = listen_sockin_accept(qentry->s.sockin.sockio, evt_tbl, 
					     num); // QUEUE_MULTI_MAX);
		if (evts > 0) {
			for (i = 0; i < evts; ++i) {
				buf = odp_buffer_from_event(evt_tbl[i]);
				tmp_hdr_tbl[i] = odp_buf_to_hdr(buf);
			}
			queue_enq_multi(qentry, tmp_hdr_tbl, evts, 0);
		}

		if (evts == -1 && nbr == 0) {
			return -1;
		}

		// Try and dequeue some more instead of waiting for another
		// loop around the scheduler.
		evts = queue_deq_multi(qentry, buf_hdr + nbr, num - nbr);
		nbr += evts;
	}

	return nbr;
}
