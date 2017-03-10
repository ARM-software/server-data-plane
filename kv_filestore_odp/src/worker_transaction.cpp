/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
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

WorkerTransaction::WorkerTransaction(uint64_t handle)
{
	my_uuid = handle;

	curState = TxState::Free;
	config = nullptr;
	wrkr = nullptr;
	hdr = nullptr;
	cmd = nullptr;
	client_evt = ODP_EVENT_INVALID;
	fileio_pool = ODP_POOL_INVALID;
	output_pkt_pool = ODP_POOL_INVALID;
	fileio_cmd_pool = ODP_POOL_INVALID;
	fileio_cmd = ODP_EVENT_INVALID;
	file_buffer = ODP_BUFFER_INVALID;
	//memset(in_flight_reps, 0, sizeof(in_flight_reps));
	for (int i = 0; i < MAX_REPLICAS; i++) {
		in_flight_reps[i].rtx = nullptr;
		in_flight_reps[i].req = ODP_EVENT_INVALID;
	}
	parent = nullptr;
	file_name.clear();
	xaction_uuid = 0;
	num_replica_peers = 0;
	odp_atomic_init_u32(&outstanding_io_ops, 0);
	op_fd = -1;
	finishing_thread_id = -1;
}

WorkerTransaction::WorkerTransaction(Config *_config,
				     Worker *_wrkr,
				     odp_event_t evt)
{
	this->initialize(_config, _wrkr, evt);
	my_uuid = 0x0;
}

void WorkerTransaction::initialize(Config *_config, Worker *_wrkr,
				   odp_event_t evt)
{
	assert(curState == Free);
	config = _config;
	client_evt = evt;
	fileio_cmd = ODP_EVENT_INVALID;
	file_buffer = ODP_BUFFER_INVALID;

	output_pkt_pool = _odph_cast_scalar(odp_pool_t,
					    std::stoi(config->getValue("output_pkt_pool")));
	fileio_pool = _odph_cast_scalar(odp_pool_t,
					std::stoi(config->getValue("fileio_pool")));
	fileio_cmd_pool = _odph_cast_scalar(odp_pool_t,
					    std::stoi(config->getValue("fileio_cmd_pool")));

	// Inspect the message header and set the state
	odp_buffer_t buf = odp_buffer_from_event(evt);

	hdr = (struct msg_header*)odp_buffer_addr(odp_buffer_from_event(evt));
	msg_type msg = (msg_type)hdr->msg_type;
	switch (msg) {
	case QDOFS_CREATE:
		curState = CreateFile;
		break;
	case QDOFS_WRITE:
		curState = WriteFile;
		break;
	case QDOFS_REPLICATE_WRITE:
		if (this->parent == nullptr) {
			curState = WriteReplica;
		} else {
			curState = WriteReplicaReq;
		}
		break;
	case QDOFS_REPLICATE_CREATE:
		if (this->parent == nullptr) {
			curState = CreateReplica;
		} else {
			curState = CreateReplicaReq;
		}
		break;
	case QDOFS_READ:
		curState = ReadFile;
		break;
	case QDOFS_ERROR:
	default:
		break;
	}

	for (int i = 0; i < MAX_REPLICAS; i++) {
		in_flight_reps[i].rtx = nullptr;
		in_flight_reps[i].req = ODP_EVENT_INVALID;
	}

	xaction_uuid = ntohll(hdr->xaction_uuid);
	// Initialize the filename to open/create
	file_name.resize(ntohl(hdr->fileid_len));
	odp_chained_buffer_copyout(buf, sizeof(struct msg_header),
				   (uint8_t*)file_name.c_str(), ntohl(hdr->fileid_len));
	// Keep a pointer to our parent worker so we can allocate replication
	// tx's
	wrkr = _wrkr;

        num_replica_peers = std::stoi(_config->getValue("numReplicas"));
	finishing_thread_id = -1;
}

void WorkerTransaction::initializeHandle(uint64_t handle)
{
	my_uuid = handle;
}

uint64_t WorkerTransaction::getHandle()
{
	return my_uuid;
}

void WorkerTransaction::setParent(WorkerTransaction *_parent)
{
	parent = _parent;
}

WorkerTransaction* WorkerTransaction::getParent()
{
	return parent;
}

int WorkerTransaction::getState()
{
	return (int)curState;
}

void WorkerTransaction::cleanObject()
{
	curState = TxState::Free;
	config = nullptr;
	wrkr = nullptr;
	hdr = nullptr;
	cmd = nullptr;
	client_evt = ODP_EVENT_INVALID;
	fileio_pool = ODP_POOL_INVALID;
	output_pkt_pool = ODP_POOL_INVALID;
	fileio_cmd_pool = ODP_POOL_INVALID;
	fileio_cmd = ODP_EVENT_INVALID;
	file_buffer = ODP_BUFFER_INVALID;
	//memset(in_flight_reps, 0, sizeof(in_flight_reps));
	for (int i = 0; i < MAX_REPLICAS; i++) {
		in_flight_reps[i].rtx = nullptr;
		in_flight_reps[i].req = ODP_EVENT_INVALID;
	}
	parent = nullptr;
	file_name.clear();
	xaction_uuid = 0;
	num_replica_peers = 0;
	odp_atomic_init_u32(&outstanding_io_ops, 0);
	op_fd = -1;
	finishing_thread_id = -1;
}

int WorkerTransaction::runStateMachine(odp_event_t evt)
{
	int ret = 0;

	// Only allow one thread to run the state machine
	// at a time.  This is actually a critical.
	tx_lock.lock();
	switch (curState) {
	case ReadFile:
		ret = submitReadIo(evt);
		break;
	case ReadFileResp:
		respondToReadIo(evt);
		break;
	case CreateFile:
		ret = submitWriteIo(evt, true);
		break;
	case WriteFile:
		ret = submitWriteIo(evt, false);
		break;
	case WriteWaitForReplica:
	case CreateWaitForReplica:
		ret = waitForReplica(evt);
		break;
	case CreateReplica:
	case WriteReplica:
		ret = submitReplicaIo(evt);
		break;
	case CreateReplicaResp:
	case WriteReplicaResp:
		ret = respondToReplicaIo(evt);
		break;
	case CreateReplicaReq:
	case WriteReplicaReq:
#ifdef DEBUG
		DEBUG_LOG("Submitting a Replica IO req\n");
#endif
		ret = submitReplicaIoReq(evt);
		break;
	case CreateReplicaReqResp:
	case WriteReplicaReqResp:
#ifdef DEBUG
		DEBUG_LOG("Got response from replica server!\n");
#endif
		ret = respondToReplicaIoReq(evt);
		break;
	case CreateFileResp:
	case WriteFileResp:
		ret = respondToWriteIo(evt);
		break;
	default:
		break;
	}
	tx_lock.unlock();

	return ret;
}

int WorkerTransaction::allocateFileCmd(odp_event_t evt)
{
	odp_event_type_t evttype;
	evttype = odp_event_type(evt);
	assert(evttype == ODP_EVENT_PACKET);

	fileio_cmd = (odp_event_t)odp_buffer_alloc(fileio_cmd_pool);
	if (fileio_cmd == ODP_EVENT_INVALID) {
		DEBUG_LOG("Could not allocate a file cmd buffer! Dropping request.\n");
		curState = Error;
		return -1;
	}

	cmd = (odp_fileio_cmd_t*)odp_buffer_addr(odp_buffer_from_event(fileio_cmd));
	cmd->uid = (void *)this;
	cmd->file_name = file_name.c_str();

	cmd->buf_offset = 0;
	cmd->fd_offset = ntohll(hdr->file_offset);
	return 0;
}

int WorkerTransaction::submitReadIo(odp_event_t evt)
{
	if (allocateFileCmd(evt) < 0) {
		DEBUG_LOG("Could not setup the file cmd buffer! Dropping request.\n");
		goto error;
	}

	cmd->cmd = ODP_FILEIO_READ;

	op_fd = open(cmd->file_name, O_RDONLY);
	if (op_fd < 0) {
		DEBUG_LOG("Could not open file %s-%d for reading! Dropping request.\n",
		       cmd->file_name, errno);
		goto error;
	}

	cmd->fd = op_fd;
	cmd->size = ntohll(hdr->file_read_len);

	// Check to see how big the file is before submitting the request.
	// Truncate request for reads that are larger than the file.
	struct stat buf;
	if (fstat(op_fd, &buf) < 0) {
		DEBUG_LOG("Could not stat file %s errno: %d! Dropping request.\n", cmd->file_name, errno);
		goto error;
	}
	if (buf.st_size < cmd->size) {
		cmd->size = buf.st_size;
	}

	cmd->buffer = odp_buffer_alloc_size(fileio_pool, cmd->size);
	if (cmd->buffer == ODP_BUFFER_INVALID) {
		DEBUG_LOG("Could not allocate buffer for read operation! Dropping request.\n");
		goto error;
	}

	// Post the command to ODP and let it complete while we go and do
	// some other things.
#ifdef DEBUG
	DEBUG_LOG("Trying to read file of %dB\n", cmd->size);
#endif
	// Process a response
	curState = ReadFileResp;

	// Could potentially have another thread process this before we exit
	// this function so set our state appropriately.
	if (odp_fileio_post_async_op(fileio_cmd) < 0) {
		DEBUG_LOG("Could not complete async read operation! Dropping request.\n");
		goto error;
	}
	return 0;

error:
	if (fileio_cmd != ODP_EVENT_INVALID) {
		if (cmd->buffer != ODP_BUFFER_INVALID)
			odp_buffer_free(cmd->buffer);
		odp_event_free(fileio_cmd);
	}
	if (op_fd >= 0) close(op_fd);
	curState = Error;
	finishing_thread_id = odp_thread_id();

	return -1;
}

int WorkerTransaction::respondToReadIo(odp_event_t evt)
{
	// These should be the same
	assert(evt == fileio_cmd);
	assert(cmd->status == cmd->size);

	odp_sockio_t sockio;
	odp_queue_t outq;
	struct msg_header *resp;

	int res = 0;
	odp_packet_t resp_pkt = odp_packet_alloc(output_pkt_pool,
						 sizeof(struct msg_header) +
						 sizeof(struct msg_footer) +
						 cmd->size);
	if (resp_pkt == ODP_PACKET_INVALID) {
		DEBUG_LOG("Failed to allocate packet for replica response!\n");
		// Clean up and bail
		curState = Error;
		res = -1;
		goto error;
	}

	// Build packet header
	resp = (struct msg_header*)odp_packet_head(resp_pkt);
	resp->magic = MAGIC_NUM_RESP;
	resp->msg_type = QDOFS_READ;
	resp->file_offset = 0;
	resp->file_read_len = 0;
	resp->fileid_len = 0;
	resp->data_len = htonl(cmd->size);
	resp->total_payload = htonl(cmd->size + sizeof(struct msg_footer));
	resp->xaction_uuid = htonll(xaction_uuid);

	// Copy response data
	odp_chained_buffer_copydata(odp_buffer_from_event(odp_packet_to_event(resp_pkt)), 
				    sizeof(struct msg_header),
				    cmd->buffer, 0, cmd->size);

	// TODO: Build packet footer, but don't care right now

	// Send out the resp pkt
	sockio = odp_sockio_get_input(odp_packet_from_event(client_evt));
	outq = odp_sockio_outq_getdef(sockio);

	if (odp_queue_enq(outq, odp_packet_to_event(resp_pkt)) < 0) {
		DEBUG_LOG("Failed to enqueue response to output queue!\n");
		// Clean up and bail.
		curState = Error;
		res = -1;
		goto error;
	}

	curState = Done;
	odp_event_free(client_evt);
error:
	// Clean up
	odp_buffer_free(cmd->buffer);
	odp_event_free(fileio_cmd);
	close(op_fd);
	finishing_thread_id = odp_thread_id();

	return res;
}

// XXX: TODO: Get read, write and create implemented and tested with a small
// test case
int WorkerTransaction::submitWriteIo(odp_event_t evt, bool create)
{
	int flags;

	if (allocateFileCmd(evt) < 0) {
		DEBUG_LOG("Could not setup the file cmd buffer! Dropping request.\n");
		curState = Error;
		goto error;
	}

	cmd->cmd = ODP_FILEIO_WRITE;

	flags = O_WRONLY;
	if (create) flags |= O_CREAT;
	op_fd = open(cmd->file_name, flags, S_IRUSR | S_IWUSR);
	if (op_fd < 0) {
		DEBUG_LOG("Could not open file %s-%d for writing! Dropping request.\n",
			  cmd->file_name, errno);
		curState = Error;
		goto error;
	}

	cmd->fd = op_fd;
	cmd->size = ntohl(hdr->data_len);
	cmd->buffer = odp_buffer_alloc_size(fileio_pool, ntohl(hdr->data_len));
	if (cmd->buffer == ODP_BUFFER_INVALID) {
		DEBUG_LOG("Could not allocate buffer for write/create operation of size %d! Dropping request.\n", ntohl(hdr->data_len));
		curState = Error;
		goto error;
	}
	odp_chained_buffer_copydata(cmd->buffer, 0,
				    odp_buffer_from_event(evt),
				    sizeof(struct msg_header) + ntohl(hdr->fileid_len),
				    ntohl(hdr->data_len));

#ifdef DEBUG
	DEBUG_LOG("Trying to write file of %dB\n", ntohl(hdr->data_len));
#endif
	// Need to initialize state before sending off async ops that could be 
	// handled by another thread.
	if (num_replica_peers > 0) {
		for (int i = 0; i < num_replica_peers; i++) {
			in_flight_reps[i].rtx = wrkr->allocateTxObj();
			if (in_flight_reps[i].rtx == nullptr) {
				DEBUG_LOG("Uh oh - ran out of WorkerTransactions for replicas!\n");
				goto error;
			}

			// Initialize the object -- similar to construction
			odp_event_t rep_evt =
				this->createReplicaEvent(in_flight_reps[i].rtx, i);

			if (rep_evt == ODP_EVENT_INVALID) {
				DEBUG_LOG("Could not allocate replication event for write!\n");
				goto error;
			}

			in_flight_reps[i].rtx->setParent(this);
			in_flight_reps[i].rtx->initialize(config, wrkr,
							  rep_evt);
			in_flight_reps[i].req = rep_evt;
		}
	}

	if (num_replica_peers > 0) {
		odp_atomic_init_u32(&outstanding_io_ops, num_replica_peers + 1);
		if (create) curState = CreateWaitForReplica;
		else	    curState = WriteWaitForReplica;
	} else {
		if (create) curState = CreateFileResp;
		else	    curState = WriteFileResp;
	}

	if (odp_fileio_post_async_op(fileio_cmd) < 0) {
		DEBUG_LOG("Could not complete async write/create operation! Dropping request.\n");
		goto error;
	}

	if (num_replica_peers > 0) {
		for (int i = 0; i < num_replica_peers; i++) {
			// Run the state machine to submit the replica IO ....
			int res = in_flight_reps[i].rtx->runStateMachine(in_flight_reps[i].req);
			if (res < 0 && i > 0) {
				DEBUG_LOG("Failed to send replica requests after sending some others!\n");
				assert(0);
			} else if (res < 0) {
				DEBUG_LOG("Failed to send the first replica req!\n");
				goto error;
			}
		}
	}

	return 0;

error:
	if (num_replica_peers > 0) {
		for (int i = 0; i < num_replica_peers; i++) {
			if (in_flight_reps[i].rtx != nullptr) {
				wrkr->freeObj(in_flight_reps[i].rtx);
				in_flight_reps[i].rtx = nullptr;
			}
			if (in_flight_reps[i].req != ODP_EVENT_INVALID) {
				odp_event_free(in_flight_reps[i].req);
				in_flight_reps[i].req = ODP_EVENT_INVALID;
			}
		}
	}

	if (fileio_cmd != ODP_EVENT_INVALID) {
		if (cmd->buffer != ODP_BUFFER_INVALID) {
			odp_buffer_free(cmd->buffer);
		}
		odp_event_free(fileio_cmd);
	}
	if (op_fd >= 0) close(op_fd);
	curState = Error;
	finishing_thread_id = odp_thread_id();

	return -1;
}

int WorkerTransaction::respondToWriteIo(odp_event_t evt)
{
	// These should be the same, but for a write with replication, this may
	// be called by the replica request. TODO: Need to devise a better check
	// to make sure things are working.
	//assert(evt == fileio_cmd);
	assert(cmd->status == cmd->size);

	odp_sockio_t sockio;
	odp_queue_t outq;
	struct msg_header *resp;
	int res = 0;
	// Create a packet with no data in it.
	odp_packet_t resp_pkt = odp_packet_alloc(output_pkt_pool,
						 sizeof(struct msg_header) +
						 sizeof(struct msg_footer));

	if (resp_pkt == ODP_PACKET_INVALID) {
		DEBUG_LOG("Failed to allocate packet for replica response!\n");
		// Clean up and bail
		curState = Error;
		res = -1;
		goto error;
	}

	// Build packet header
	resp = (struct msg_header*)odp_packet_head(resp_pkt);
	resp->magic = MAGIC_NUM_RESP;
	if (curState == WriteFileResp) {
		resp->msg_type = QDOFS_WRITE;
	} else if (curState == CreateFileResp) {
		resp->msg_type = QDOFS_CREATE;
	}
	resp->file_offset = 0;
	resp->file_read_len = 0;
	resp->fileid_len = 0;
	resp->data_len = 0;
	resp->total_payload = htonl(sizeof(struct msg_footer));
	resp->xaction_uuid = htonll(xaction_uuid);

	// TODO: Build packet footer, but don't care right now

	// Send out the resp pkt
	sockio = odp_sockio_get_input(odp_packet_from_event(client_evt));
	outq = odp_sockio_outq_getdef(sockio);

	if (odp_queue_enq(outq, odp_packet_to_event(resp_pkt)) < 0) {
		DEBUG_LOG("Failed to enqueue response to output queue!\n");
		// Clean up and bail
		curState = Error;
		res = -1;
		goto error;
	}

	curState = Done;
	odp_event_free(client_evt);
error:
	// Clean up
	odp_buffer_free(cmd->buffer);
	odp_event_free(fileio_cmd);
	close(op_fd);
	finishing_thread_id = odp_thread_id();

	return res;
}

odp_event_t WorkerTransaction::createReplicaEvent(WorkerTransaction *rtx, int seq_num)
{
	odp_packet_t replica_pkt = odp_packet_alloc(output_pkt_pool,
						    sizeof(struct msg_header) +
						    ntohl(hdr->total_payload));
	if (replica_pkt == ODP_PACKET_INVALID)
		return ODP_EVENT_INVALID;

	struct msg_header *replica = (struct
				      msg_header*)odp_packet_head(replica_pkt);
	replica->magic = MAGIC_NUM;

	if (curState == CreateFile) replica->msg_type = QDOFS_REPLICATE_CREATE;
	else replica->msg_type = QDOFS_REPLICATE_WRITE;

	replica->file_offset = hdr->file_offset;
	replica->file_read_len = 0;
	replica->fileid_len = hdr->fileid_len;
	replica->data_len = hdr->data_len;
	replica->total_payload = hdr->total_payload;
	replica->xaction_uuid = htonll(rtx->getHandle() + seq_num);

	odp_chained_buffer_copydata(odp_buffer_from_event(odp_packet_to_event(replica_pkt)), 
				    sizeof(struct msg_header),
				    odp_buffer_from_event(this->client_evt),
				    sizeof(struct msg_header),
				    ntohl(hdr->total_payload));

	return odp_packet_to_event(replica_pkt);
}

int WorkerTransaction::submitReplicaIoReq(odp_event_t evt)
{
	if (curState == CreateReplicaReqResp) curState = CreateReplicaReqResp;
	else curState = WriteReplicaReqResp;

	int seq_num = ntohll(((struct msg_header*)odp_buffer_addr(
			     odp_buffer_from_event(evt)))->xaction_uuid)
		       & 0x000000003fffffff;
	return wrkr->sendReplicaRequest(evt, seq_num);
}

int WorkerTransaction::submitReplicaIo(odp_event_t evt)
{
	int flags;

	if (allocateFileCmd(evt) < 0) {
		DEBUG_LOG("Could not setup the file cmd buffer! Dropping request.\n");
		curState = Error;
		goto error;
	}

	cmd->cmd = ODP_FILEIO_WRITE;

	flags = O_WRONLY;
	if (curState == CreateReplica) flags |= O_CREAT;
	op_fd = open(cmd->file_name, flags, S_IRUSR | S_IWUSR);
	if (op_fd < 0) {
		DEBUG_LOG("Could not open file %s,%d for writing! Dropping request.\n",
		       cmd->file_name, errno);
		curState = Error;
		goto error;
	}

	cmd->fd = op_fd;
	cmd->size = ntohl(hdr->data_len);
	cmd->buffer = odp_buffer_alloc_size(fileio_pool, ntohl(hdr->data_len));
	if (cmd->buffer == ODP_BUFFER_INVALID) {
		DEBUG_LOG("Could not allocate buffer for write/create operation! Dropping request.\n");
		curState = Error;
		goto error;
	}
	odp_chained_buffer_copydata(cmd->buffer, 0,
				    odp_buffer_from_event(evt),
				    sizeof(struct msg_header) + ntohl(hdr->fileid_len),
				    ntohl(hdr->data_len));

	// XXX: Set state first in case our async IO just happens to complete
	//      before hand.
	if (curState == CreateReplica) curState = CreateReplicaResp;
	else if (curState == WriteReplica) curState = WriteReplicaResp;

	if (odp_fileio_post_async_op(fileio_cmd) < 0) {
		DEBUG_LOG("Could not complete async write/create operation! Dropping request.\n");
		curState = Error;
		goto error;
	}

	return 0;
error:
	if (fileio_cmd != ODP_EVENT_INVALID) {
		if (cmd->buffer != ODP_BUFFER_INVALID) {
			odp_buffer_free(cmd->buffer);
		}
		odp_event_free(fileio_cmd);
	}

	if (op_fd >= 0) close(op_fd);
	finishing_thread_id = odp_thread_id();
	return -1;
}

int WorkerTransaction::respondToReplicaIo(odp_event_t evt)
{
	// These should be the same
	assert(evt != ODP_EVENT_INVALID);
	assert(evt == fileio_cmd);
        assert(cmd->status == cmd->size);

	odp_sockio_t sockio;
	odp_queue_t outq;
	struct msg_header *resp;
	int res = 0;
	// Create a packet with no data in it.
	odp_packet_t resp_pkt = odp_packet_alloc(output_pkt_pool,
						 sizeof(struct msg_header) +
						 sizeof(struct msg_footer));
	if (resp_pkt == ODP_PACKET_INVALID) {
		DEBUG_LOG("Failed to allocate packet for replica response!\n");
		// Clean up and bail
		curState = Error;
		res = -1;
		goto error;
	}

	// Build packet header
	resp = (struct msg_header*)odp_packet_head(resp_pkt);
	resp->magic = MAGIC_NUM_RESP;
	if (curState == CreateReplicaResp) resp->msg_type = QDOFS_REPLICATE_CREATE;
	else resp->msg_type = QDOFS_REPLICATE_WRITE;

	resp->file_offset = 0;
	resp->file_read_len = 0;
	resp->fileid_len = 0;
	resp->data_len = 0;
	resp->total_payload = htonl(sizeof(struct msg_footer));
	resp->xaction_uuid = htonll(xaction_uuid);

	// TODO: Build packet footer, but don't care right now

	// Send out the resp pkt
	sockio = odp_sockio_get_input(odp_packet_from_event(client_evt));
	outq = odp_sockio_outq_getdef(sockio);

#ifdef DEBUG
	DEBUG_LOG("Sending out Replica response\n");
#endif
	if (odp_queue_enq(outq, odp_packet_to_event(resp_pkt)) < 0) {
		// Clean up and bail
		curState = Error;
		res = -1;
		goto error;
	}

	curState = Done;
	odp_event_free(client_evt);
error:
	// Clean up
	odp_buffer_free(cmd->buffer);
	odp_event_free(fileio_cmd);
	close(op_fd);
	finishing_thread_id = odp_thread_id();

	return res;
}

// If we run into an unrecoverable error, notify the client and try to clean up 
// the best we can.
int WorkerTransaction::sendErrorToClient(odp_event_t evt)
{
	odp_queue_t outq;
	odp_sockio_t sockio;
	struct msg_header *resp;
	int res = 0;
	// Create a packet with no data in it.
	odp_packet_t resp_pkt = odp_packet_alloc(output_pkt_pool,
						 sizeof(struct msg_header) +
						 sizeof(struct msg_footer));

	if (resp_pkt == ODP_PACKET_INVALID) {
		DEBUG_LOG("Failed to allocate packet for error response!\n");
		// Clean up and bail
		curState = Error;
		res = -1;
		goto error;
	}

	// Build packet header
	resp = (struct msg_header*)odp_packet_head(resp_pkt);
	resp->magic = MAGIC_NUM_RESP;
	resp->msg_type = QDOFS_ERROR;

	resp->file_offset = 0;
	resp->file_read_len = 0;
	resp->fileid_len = 0;
	resp->data_len = 0;
	resp->total_payload = htonl(sizeof(struct msg_footer));
	resp->xaction_uuid = htonll(xaction_uuid);

	// TODO: Build packet footer, but don't care right now

	// Send out the resp pkt
	sockio = odp_sockio_get_input(odp_packet_from_event(client_evt));
	outq = odp_sockio_outq_getdef(sockio);

	if (odp_queue_enq(outq, odp_packet_to_event(resp_pkt)) < 0) {
		DEBUG_LOG("Failed to enqueue response to output queue!\n");
		// Clean up and bail
		curState = Error;
		res = -1;
		goto error;
	}

	// Clean up
	curState = Done;
error:
	odp_event_free(client_evt);
	finishing_thread_id = odp_thread_id();

	return res;
}

//      Need to document the state machine because it is starting to get a touch
//      confusing.
int WorkerTransaction::respondToReplicaIoReq(odp_event_t evt)
{
	struct msg_header *resp = (struct
				   msg_header*)odp_packet_head(odp_packet_from_event(evt));

#ifdef DEBUG
	DEBUG_LOG("Respond to replica IO req\n");
#endif
	// check to make sure the response lines up with what was sent, then
	// poke the parent tx remove waiting for this replica request
	if (resp->magic == MAGIC_NUM_RESP &&
	    (resp->msg_type == QDOFS_REPLICATE_WRITE ||
	     resp->msg_type == QDOFS_REPLICATE_CREATE ||
	     resp->msg_type == QDOFS_ERROR) &&
	    ntohll(resp->xaction_uuid) == xaction_uuid) {
		// We have a valid response, clean up
		assert(client_evt != ODP_EVENT_INVALID);
		if (resp->msg_type == QDOFS_ERROR) {
			DEBUG_LOG("Got an error response to a replica request\n");
		}

		//odp_event_free(client_evt); //XXX: sockio has already deleted this guy.
		client_evt = ODP_EVENT_INVALID;
		fileio_pool = ODP_POOL_INVALID;
		output_pkt_pool = ODP_POOL_INVALID;
		fileio_cmd_pool = ODP_POOL_INVALID;

		if (parent) {
			uint64_t seq_num = xaction_uuid & 0x000000003fffffff;
			assert(parent->in_flight_reps[seq_num].rtx != nullptr);
			assert(parent->in_flight_reps[seq_num].req != ODP_EVENT_INVALID);

			parent->in_flight_reps[seq_num].rtx = nullptr;
			parent->in_flight_reps[seq_num].req = ODP_EVENT_INVALID;
		}
		curState = Done;
		finishing_thread_id = odp_thread_id();

		// This event can be freed here
		odp_event_free(evt);
	} else {
		DEBUG_LOG("Got a response to an transaction that is not of the proper type!\n");
		assert(0);
	}

	return 0;
}

int WorkerTransaction::waitForReplica(odp_event_t evt)
{
	// check to make sure all replicas have completed, then change our
	// state and run the state machine again re-entrantly.
	// All replica responses and the local response route through here
	// so the last one will cause the write to fully complete.
	uint32_t res = odp_atomic_fetch_sub_u32(&outstanding_io_ops, 1);
	// Should never see a result outside this range, and if we do,
	// somehow getting more responses than expected.
	assert(res > 0 && res <= (num_replica_peers + 1));

	if (res == 1) {
		if (curState == WriteWaitForReplica) {
			curState = WriteFileResp;
		} else if (curState == CreateWaitForReplica) {
			curState = CreateFileResp;
		}
		return this->runStateMachine(evt);
	}
	return 0;
}
