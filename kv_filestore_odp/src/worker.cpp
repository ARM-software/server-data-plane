/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <arpa/inet.h>
#include <assert.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "include/config.hh"
#include "include/protocol.hh"
#include "include/worker.hh"
#include "include/util.hh"

#include <odp/api/stream_packetizer.h>
#include <odp/api/chained_buffer.h>
#include <odp/helper/strong_types.h>

// Just do 1 event at a time for now for testing
static const int MAX_BUFS = 20;
static const int MAX_RETRIES = 4096;

void* Worker::WorkerStart(void *arg)
{
	Config *conf = (Config*)arg;

	Worker *odp_worker = new Worker(conf);
	// Let the thread go to work calling odp_schedule()
	odp_worker->processEvents();
	return NULL;
}

Worker::Worker(Config *_conf)
{
	conf = _conf;
	input_pkt_pool = _odph_cast_scalar(odp_pool_t,
					   std::stoi(conf->getValue("input_pkt_pool")));

	for (int i = 0; i < MAX_PEERS; i++) {
		replica_sfds[i] = -1;
		replica_sockios[i] = ODP_SOCKIO_INVALID;
	}
	setupReplicaConns();

	// Allocate a pool for this
	objPool = new
		ObjPool<WorkerTransaction>(std::stoi(conf->getValue("worker_tx_pool_size")));
}

// Make connections to the replica servers, will have to use timeouts here and
// max retries in case something just blows up.
void Worker::setupReplicaConns()
{
	num_replica_peers = std::stoi(conf->getValue("numReplicas"));

	for (int i = 0; i < num_replica_peers; i++) {
		int retries = 0;
		std::string addr_key = "replica-" + std::to_string(i) + "-addr";
		std::string port_key = "replica-" + std::to_string(i) + "-port";
		std::string addr = conf->getValue(addr_key);
		std::string port = conf->getValue(port_key);
		int sfd = createSocket(addr, port);
		while (sfd < 0) {
			// Looks like we have to wait
			sleep(1);
			retries++;
			if (retries >= MAX_RETRIES) {
				DEBUG_LOG("Can't contact replica server %s:%s.\n",
				       addr.c_str(), port.c_str());
				assert(0);
			}
			sfd = createSocket(addr, port);
		}

		odp_sockio_t sockio = odp_sockio_create_queues(sfd, input_pkt_pool,
							       ODP_SOCKIO_TYPE_STREAM,
							       ODP_SOCKIO_CREATE_ALL_QUEUES);
		if (sockio == ODP_SOCKIO_INVALID) {
			// Lets just try the next server
			DEBUG_LOG("odp_sockio_open() failed for replica server %s:%s.\n", 
			       addr.c_str(), port.c_str());
			continue;
		}
		replica_sockios[i] = sockio;
		odp_packetizer_t pktizer;
		odp_packetizer_entry_t pktizer_entry;

		// Create a packetizer for the socket for responses
		// from replica servers.
		pktizer_entry.pool = input_pkt_pool;
		pktizer_entry.header_size = sizeof(struct msg_header);
		pktizer_entry.size_offset = offsetof(struct msg_header,
						     total_payload);
		pktizer_entry.num_bytes = sizeof(uint32_t);

		pktizer = odp_packetizer_create(pktizer_entry);
		odp_assign_packetizer_sockio(sockio, pktizer, input_pkt_pool);
		odp_socket_io_start(sockio);

		DEBUG_LOG("Connected to replica server %s:%s\n", addr.c_str(),
		       port.c_str());
	}
}

void Worker::processConnectionEvent(odp_event_t c_evt)
{
	// Get the connect event
	connect_evt *ce = (connect_evt*)odp_buffer_addr(odp_buffer_from_event(c_evt));

	odp_packetizer_t pktizer;
	odp_packetizer_entry_t pktizer_entry;
	odp_sockio_t sockio;

	sockio = odp_sockio_create_queues(ce->sfd, input_pkt_pool,
					  ODP_SOCKIO_TYPE_STREAM,
					  ODP_SOCKIO_CREATE_ALL_QUEUES);
	if (sockio == ODP_SOCKIO_INVALID) {
		DEBUG_LOG("odp_sockio_open() failed!\n");
		return;
	}

	// Create a packetizer for the stream socket with the simple binary
	// protocol
	pktizer_entry.pool = input_pkt_pool;
	pktizer_entry.header_size = sizeof(struct msg_header);
	pktizer_entry.size_offset = offsetof(struct msg_header, total_payload);
	pktizer_entry.num_bytes = sizeof(uint32_t);

	pktizer = odp_packetizer_create(pktizer_entry);
	odp_assign_packetizer_sockio(sockio, pktizer, input_pkt_pool);

	// Socket input created and packetizer available, start socket in
	// scheduler code now
	odp_socket_io_start(sockio);

	return;
}

// Process a packet event, set up a transaction worker
void Worker::processRequest(odp_event_t evt)
{
	struct msg_header *hdr;

	hdr = (struct msg_header*)odp_buffer_addr(odp_buffer_from_event(evt));

	if (hdr->magic == MAGIC_NUM) {
		// Got a packet to process.
		// Check CRC .... do later ...
		//WorkerTransaction *tx = new WorkerTransaction(conf, evt);
		WorkerTransaction *tx = objPool->allocateObj();
		if (tx == nullptr) {
			DEBUG_LOG("Uh oh - ran out of WorkerTransactions!\n");
			return;
		}
		// Initialize the object -- similar to construction
		tx->initialize(conf, this, evt);

		assert(tx->getState());
		// Run the state machine
		int res = tx->runStateMachine(evt);

		if (tx->isDone() && tx->txFinishedBy() == odp_thread_id()) {
		       objPool->freeObj(tx);
		} else if (tx->isError() && tx->txFinishedBy() == odp_thread_id()) {
			// If we error, it is unrecoverable, drop tx and clean
			// up!
			if (tx->sendErrorToClient(evt) < 0) {
				DEBUG_LOG("Could not send an error packet!\n");
				assert(0);
			}
			objPool->freeObj(tx);
		}
	} else if (hdr->magic == MAGIC_NUM_RESP) {
		// Find the worker tx this belongs to and its parent.
		// This has to be a replication fullfill response
		assert(hdr->msg_type == QDOFS_REPLICATE_WRITE ||
		       hdr->msg_type == QDOFS_REPLICATE_CREATE ||
		       hdr->msg_type == QDOFS_ERROR);
#ifdef DEBUG
		DEBUG_LOG("Got a response to a replica request\n");
#endif
		WorkerTransaction *rtx =
			objPool->findItem(ntohll(hdr->xaction_uuid));
		WorkerTransaction *ptx = rtx->getParent();
		// Check to make sure everything is going as planned
		assert(rtx->getState());
		assert(ptx != nullptr);
		assert(ptx->getState());

		// Run the state machines of both, and if both complete
		// then we can reclaim the resources.
		int res = rtx->runStateMachine(evt);
		if (rtx->isDone() && rtx->txFinishedBy() == odp_thread_id()) {
			objPool->freeObj(rtx);
		} else if (rtx->isError() && rtx->txFinishedBy() == odp_thread_id()) {
			DEBUG_LOG("Replica transaction errored!\n");
			assert(0);
		}
		// Only let the replica tx that is last to complete do the state machine
		// of the parent to avoid race conditions.  Use the atomic 
		// sub and fetch op from ODP to perform this light-weight mutual
		// exclusion.
		res = ptx->runStateMachine(evt);
		if (ptx->isDone() && ptx->txFinishedBy() == odp_thread_id()) {
			objPool->freeObj(ptx);
		} else if (ptx->isError() && ptx->txFinishedBy() == odp_thread_id()) {
			DEBUG_LOG("Parent transaction errored!\n");
			if (ptx->sendErrorToClient(evt) < 0) {
				DEBUG_LOG("Could not send an error packet!\n");
				assert(0);
			} else {
				objPool->freeObj(ptx);
			}
		}
	} else {
		DEBUG_LOG("Uh oh - got an unrecognized packet! Dropping it.\n");
		assert(0);
	}
}

// Process a file io completion
void Worker::processFileCompl(odp_event_t evt)
{
	odp_fileio_cmd_t *cmd;
	cmd = (odp_fileio_cmd_t *)odp_buffer_addr(odp_buffer_from_event(evt));

	// Check to see if the tx still exists
	WorkerTransaction *tx = (WorkerTransaction*)cmd->uid;
	assert(tx->getState());

	int res = tx->runStateMachine(evt);
	if (tx->isDone()) {
		// State machine done, clean up
		objPool->freeObj(tx);
	} else if (res < 0) {
		if (tx->sendErrorToClient(evt) < 0) {
			DEBUG_LOG("Could not send an error packet!\n");
			assert(0);
		} else {
			objPool->freeObj(tx);
		}
	}
}

void Worker::processEvents()
{
	odp_queue_t inq;
	odp_event_t out_buf[MAX_BUFS];
	int len;

	// Sit forever trying to get packets from the scheduler
	while(1) {
		len = odp_schedule_multi(&inq, ODP_SCHED_WAIT, out_buf,
					 MAX_BUFS);
#ifdef DEBUG
		DEBUG_LOG("Got %d messages to process\n", len);
#endif

		for (int i = 0; i < len; i++) {
			odp_event_type_t evttype;
			evttype = odp_event_type(out_buf[i]);
			switch(evttype) {
			case ODP_EVENT_PACKET:
				processRequest(out_buf[i]);
				break;
			case ODP_EVENT_SOCKET_CONNECT:
				processConnectionEvent(out_buf[i]);
				break;
			case ODP_EVENT_FILE_IO_COMPL:
				processFileCompl(out_buf[i]);
				break;
			default:
#ifdef DEBUG
				DEBUG_LOG("Unknown event encountered\n");
#endif
				break;
			}
			out_buf[i] = ODP_EVENT_INVALID;
		}
	}
}

int Worker::sendReplicaRequest(odp_event_t evt, int replica_num)
{
	// Send out the replica request pkt
	odp_sockio_t sockio = replica_sockios[replica_num];
	odp_queue_t outq = odp_sockio_outq_getdef(sockio);

	return odp_queue_enq(outq, evt);
}
