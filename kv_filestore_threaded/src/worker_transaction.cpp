/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "include/config.hh"
#include "include/protocol.hh"
#include "include/worker.hh"
#include "include/util.hh"

WorkerTransaction::WorkerTransaction(Config *conf, Worker *_wrkr,
				     unsigned id, std::vector<uint8_t>&& buf)
{
	curState = TxState::Free;
	config = conf;
	wrkr = _wrkr;
	num_replica_peers = std::stoi(config->getValue("numReplicas"));
	pipe_id = id;

	in_flight_reps.resize(num_replica_peers);

	// input packet;
	in_pkt = buf;
	parent = nullptr;
	hdr = (struct msg_header*)in_pkt.data();
	outstanding_io_ops = 0;
	finishing_thread_id = pthread_self();

	// Inspect the message header and set the state
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

	xaction_uuid = ntohll(hdr->xaction_uuid);
}

WorkerTransaction::WorkerTransaction(Config *conf, Worker *_wrkr)
{
	curState = TxState::Free;
	config = conf;
	wrkr = _wrkr;
	num_replica_peers = 0;
	pipe_id = 0;

	// input packet;
	parent = nullptr;
	outstanding_io_ops = 0;
	finishing_thread_id = pthread_self();
}

WorkerTransaction::~WorkerTransaction()
{}

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

uint64_t WorkerTransaction::getPipeIdx()
{
	return pipe_id;
}

std::vector<uint8_t>&& WorkerTransaction::getOutPacket()
{
	return std::move(out_pkt);
}

void WorkerTransaction::setInPacket(std::vector<uint8_t>&& pkt)
{
	in_pkt = pkt;
}

int WorkerTransaction::runStateMachine()
{
	int ret = 0;

	// Only allow one thread to run the state machine
	// at a time.  This is actually a critical.
	tx_lock.lock();
	switch (curState) {
	case ReadFile:
		ret = submitReadIo();
		break;
	case ReadFileResp:
		respondToReadIo();
		break;
	case CreateFile:
		ret = submitWriteIo(true);
		break;
	case WriteFile:
		ret = submitWriteIo(false);
		break;
	case WriteWaitForReplica:
	case CreateWaitForReplica:
		ret = waitForReplica();
		break;
	case CreateReplica:
	case WriteReplica:
		ret = submitReplicaIo();
		break;
	case CreateReplicaResp:
	case WriteReplicaResp:
		ret = respondToReplicaIo();
		break;
	case CreateReplicaReq:
	case WriteReplicaReq:
#ifdef DEBUG
		DEBUG_LOG("Submitting a Replica IO req\n");
#endif
		ret = submitReplicaIoReq();
		break;
	case CreateReplicaReqResp:
	case WriteReplicaReqResp:
#ifdef DEBUG
		DEBUG_LOG("Got response from replica server!\n");
#endif
		ret = respondToReplicaIoReq();
		break;
	case CreateFileResp:
	case WriteFileResp:
		ret = respondToWriteIo();
		break;
	default:
		break;
	}
	tx_lock.unlock();

	return ret;
}

void WorkerTransaction::allocateFileCmd(FileIOCmd::Cmd cmd)
{
	file_io_cmd.cmd = cmd;
	file_io_cmd.res = FileIOCmd::Res::InProgress;

	file_io_cmd.file_offset = ntohll(hdr->file_offset);
	file_io_cmd.filename.resize(ntohl(hdr->fileid_len));
	memcpy(const_cast<char*>(file_io_cmd.filename.data()),
	       (in_pkt.data() + sizeof(struct msg_header)),
	       ntohl(hdr->fileid_len));

	if (cmd == FileIOCmd::Cmd::Read) {
		file_io_cmd.file_op_len = ntohll(hdr->file_read_len);
		file_io_cmd.payload_buf.resize(file_io_cmd.file_op_len, 0);
	} else {
		file_io_cmd.file_op_len = ntohl(hdr->data_len);
		file_io_cmd.payload_buf.resize(file_io_cmd.file_op_len, 0);
		memcpy(file_io_cmd.payload_buf.data(),
		       in_pkt.data() + sizeof(struct msg_header) + ntohl(hdr->fileid_len),
		       file_io_cmd.file_op_len);

	}
}

int WorkerTransaction::submitReadIo()
{
	try {
		allocateFileCmd(FileIOCmd::Cmd::Read);

		// Post the command to FileIO and let it complete while we go and do
		// some other things.
#ifdef DEBUG
		DEBUG_LOG("Trying to read file of %luB\n",
			  file_io_cmd.file_op_len);
#endif
		// Process a response
		curState = ReadFileResp;

		// Could potentially have another thread process this before we exit
		// this function so set our state appropriately.
		wrkr->submitFileIO(this);

		return 0;
	} catch (...) {
		curState = Error;
		finishing_thread_id = pthread_self();
		return -1;
	}
}

int WorkerTransaction::respondToReadIo()
{
	// These should be the same
	assert(file_io_cmd.res == FileIOCmd::Res::Success);

	try {
		struct msg_header *resp;
		out_pkt.resize(sizeof(struct msg_header) +
			       sizeof(struct msg_footer) +
			       file_io_cmd.file_op_len, 0);

		// Build packet header
		resp = (struct msg_header*)out_pkt.data();
		resp->magic = MAGIC_NUM_RESP;
		resp->msg_type = QDOFS_READ;
		resp->file_offset = 0;
		resp->file_read_len = 0;
		resp->fileid_len = 0;
		resp->data_len = htonl(file_io_cmd.file_op_len);
		resp->total_payload = htonl(file_io_cmd.file_op_len
					    + sizeof(struct msg_footer));
		resp->xaction_uuid = htonll(xaction_uuid);

		// Copy response data
		memcpy(out_pkt.data() + sizeof(struct msg_header),
		       file_io_cmd.payload_buf.data(), file_io_cmd.file_op_len);

		// TODO: Build packet footer, but don't care right now

		// Send out the resp pkt
		wrkr->appendReplyToClient(this, pipe_id);

		curState = Done;
		finishing_thread_id = pthread_self();
	} catch (...) {
		curState = Error;
		finishing_thread_id = pthread_self();
		return -1;
	}

	return 0;
}

int WorkerTransaction::submitWriteIo(bool create)
{
	try {
		allocateFileCmd((create) ? FileIOCmd::Cmd::Create :
				FileIOCmd::Cmd::Write);

#ifdef DEBUG
		DEBUG_LOG("Trying to write file of %dB\n", ntohl(hdr->data_len));
#endif

		// Need to initialize state before sending off async ops that could be 
		// handled by another thread.
		if (num_replica_peers > 0) {
			for (unsigned i = 0; i < num_replica_peers; i++) {
				in_flight_reps[i].rtx =
					this->createReplicaTx(i);
			}
		}

		if (num_replica_peers > 0) {
			outstanding_io_ops = num_replica_peers + 1;
			if (create) curState = CreateWaitForReplica;
			else curState = WriteWaitForReplica;
		} else {
			if (create) curState = CreateFileResp;
			else	    curState = WriteFileResp;
		}

		wrkr->submitFileIO(this);

		if (num_replica_peers > 0) {
			for (unsigned i = 0; i < num_replica_peers; i++) {
				// Run the state machine to submit the replica IO ....
				in_flight_reps[i].rtx->runStateMachine();
			}
		}

		return 0;
	} catch (...) {
		if (num_replica_peers > 0) {
			for (unsigned i = 0; i < num_replica_peers; i++) {
				delete in_flight_reps[i].rtx;
			}
			in_flight_reps.resize(0);
		}
		curState = Error;
		finishing_thread_id = pthread_self();
		return -1;
	}

	return 0;
}

int WorkerTransaction::respondToWriteIo()
{
	assert(file_io_cmd.res == FileIOCmd::Res::Success);

	struct msg_header *resp;
	int res = 0;
	try {
		// Create a packet with no data in it.
		out_pkt.resize(sizeof(struct msg_header) +
			       sizeof(struct msg_footer), 0);

		// Build packet header
		resp = (struct msg_header*)out_pkt.data();
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
		wrkr->appendReplyToClient(this, pipe_id);
		curState = Done;
		res = 0;
	} catch (...) {
		curState = Error;
		res = -1;
	}

	finishing_thread_id = pthread_self();
	return res;
}

WorkerTransaction* WorkerTransaction::createReplicaTx(int seq_num)
{
	WorkerTransaction *rtx = new WorkerTransaction(config, wrkr);

	rtx->out_pkt.resize(in_pkt.size(), 0);
	struct msg_header *replica = (struct msg_header*)rtx->out_pkt.data();
	replica->magic = MAGIC_NUM;

	if (curState == CreateFile) {
		rtx->curState = CreateReplicaReq;
		replica->msg_type = QDOFS_REPLICATE_CREATE;
	} else {
		rtx->curState = WriteReplicaReq;
		replica->msg_type = QDOFS_REPLICATE_WRITE;
	}

	replica->file_offset = hdr->file_offset;
	replica->file_read_len = 0;
	replica->fileid_len = hdr->fileid_len;
	replica->data_len = hdr->data_len;
	replica->total_payload = hdr->total_payload;

	// This is the hash I need to use?
	replica->xaction_uuid = htonll(seq_num);
	rtx->xaction_uuid = seq_num;

	memcpy(rtx->out_pkt.data() + sizeof(struct msg_header),
	       in_pkt.data() + sizeof(struct msg_header),
	       in_pkt.size() - sizeof(struct msg_header));
	rtx->setParent(this);

	return rtx;
}

void WorkerTransaction::setReplicaReqUuid(uint64_t uuid)
{
	struct msg_header *replica_hdr = (struct msg_header*)out_pkt.data();
	replica_hdr->xaction_uuid = htonll(uuid);
	xaction_uuid = uuid;
}

int WorkerTransaction::submitReplicaIoReq()
{
	if (curState == CreateReplicaReqResp) curState = CreateReplicaReqResp;
	else curState = WriteReplicaReqResp;

	wrkr->appendReplicaRequest(this, this->xaction_uuid);
	return 0;
}

int WorkerTransaction::submitReplicaIo()
{
	try {
		allocateFileCmd((curState == CreateReplica) ?
				FileIOCmd::Cmd::Create : FileIOCmd::Cmd::Write);

		// Set state first in case our async IO just happens to complete
		// before hand.
		if (curState == CreateReplica) curState = CreateReplicaResp;
		else if (curState == WriteReplica) curState = WriteReplicaResp;

		wrkr->submitFileIO(this);

		return 0;
	} catch (...) {
		finishing_thread_id = pthread_self();
		curState = Error;
		return -1;
	}
}

int WorkerTransaction::respondToReplicaIo()
{
	assert(file_io_cmd.res == FileIOCmd::Res::Success);

	struct msg_header *resp;
	int res = 0;
	try {
		// Create a packet with no data in it.
		out_pkt.resize(sizeof(struct msg_header) +
			       sizeof(struct msg_footer), 0);

		// Build packet header
		resp = (struct msg_header*)out_pkt.data();
		resp->magic = MAGIC_NUM_RESP;
		if (curState == WriteReplicaResp) {
			resp->msg_type = QDOFS_REPLICATE_WRITE;
		} else if (curState == CreateReplicaResp) {
			resp->msg_type = QDOFS_REPLICATE_CREATE;
		}
		resp->file_offset = 0;
		resp->file_read_len = 0;
		resp->fileid_len = 0;
		resp->data_len = 0;
		resp->total_payload = htonl(sizeof(struct msg_footer));
		resp->xaction_uuid = htonll(xaction_uuid);

		// TODO: Build packet footer, but don't care right now

		// Send out the resp pkt
		wrkr->appendReplyToClient(this, pipe_id);
		curState = Done;
		res = 0;
	} catch (...) {
		curState = Error;
		res = -1;
	}
	finishing_thread_id = pthread_self();
	return res;
}

// If we run into an unrecoverable error, notify the client and try to clean up 
// the best we can.
int WorkerTransaction::sendErrorToClient()
{
	struct msg_header *resp;
	int res = 0;
	try {
		// Create a packet with no data in it.
		out_pkt.resize(sizeof(struct msg_header) +
			       sizeof(struct msg_footer), 0);

		// Build packet header
		resp = (struct msg_header*)out_pkt.data();
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
		wrkr->appendReplyToClient(this, pipe_id);
		curState = Done;
		res = 0;
	} catch (...) {
		curState = Error;
		res = -1;
	}

	finishing_thread_id = pthread_self();
	return res;
}

int WorkerTransaction::respondToReplicaIoReq()
{
	struct msg_header *resp = (struct msg_header*)in_pkt.data();

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
		if (resp->msg_type == QDOFS_ERROR) {
			DEBUG_LOG("Got an error response to a replica request\n");
		}

		if (parent) {
			uint64_t seq_num = xaction_uuid & (MAX_REPLICAS - 1) ;
			assert(parent->in_flight_reps[seq_num].rtx != nullptr);
			parent->in_flight_reps[seq_num].rtx = nullptr;
		}
		curState = Done;
		finishing_thread_id = pthread_self();

	} else {
		DEBUG_LOG("Got a response to an transaction that is not of the proper type!\n");
		assert(0);
	}

	return 0;
}

int WorkerTransaction::waitForReplica()
{
	// check to make sure all replicas have completed, then change our
	// state and run the state machine again re-entrantly.
	// All replica responses and the local response route through here
	// so the last one will cause the write to fully complete.
	outstanding_io_ops--;
	// Should never see a result outside this range, and if we do,
	// somehow getting more responses than expected.
	assert(outstanding_io_ops >= 0 && outstanding_io_ops < (num_replica_peers + 1));

	if (outstanding_io_ops == 0) {
		if (curState == WriteWaitForReplica) {
			curState = WriteFileResp;
		} else if (curState == CreateWaitForReplica) {
			curState = CreateFileResp;
		}
		return this->runStateMachine();
	}
	return 0;
}
