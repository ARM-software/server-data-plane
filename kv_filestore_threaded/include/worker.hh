/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef WORKER_HH
#define WORKER_HH

#include <map>
#include "include/acceptor.hh"
#include "include/pipe.hh"
#include "include/exception.hh"
#include "include/protocol.hh"
#include "include/file_io.hh"
#include "include/util.hh"

// These are the same for now ... but in something more complicated, like
// full blown Ceph or Lustre, your peers may be all nodes, but you only
// replicate to a handful.
#define MAX_PEERS 16
#define MAX_REPLICAS 16
#define UUID_SHIFT 4 // log2 of MAX_REPLICAS

class Worker;

class WorkerException : public QdofsException
{
	using QdofsException::QdofsException;

	virtual const char* what() const throw()
	{
		std::string str = "Worker exception: " + msg + "\n";
		return str.c_str();
	}
};

// This holds the state of each transaction as events
// come in from ODP to process them.
class WorkerTransaction
{
public:
	WorkerTransaction(Config *config, Worker *wrkr,
			  unsigned id, std::vector<uint8_t>&& buf);
	WorkerTransaction(Config *config, Worker *wrkr);

	~WorkerTransaction();

	// Run the transaction state machine
	int runStateMachine();
	bool isDone()
	{
		if (curState == Done) return true;
		else return false;
	}
	bool isError()
	{
		if (curState == Error ||
		    curState == ErrorReplica) return true;
		else return false;
	}

	bool isReplicaReq() {
		if (curState == WriteReplica ||
		    curState == WriteReplicaResp ||
		    curState == CreateReplica ||
		    curState == CreateReplicaResp ||
		    curState == ErrorReplica) {
			return true;
		}
		return false;
	}

	int txFinishedBy()
	{
		return finishing_thread_id;
	}

	FileIOCmd& getFileOp()
	{
		return file_io_cmd;
	}

	uint64_t getTxUuid()
	{
		return xaction_uuid;
	}

	void setParent(WorkerTransaction *parent);
	WorkerTransaction* getParent();
	void notifyParent(int idx);
	int getState();
	int sendErrorToClient();
	void setReplicaReqUuid(uint64_t uuid);

	void setInPacket(std::vector<uint8_t>&& in_pkt);

	std::vector<uint8_t>&& getOutPacket();
	uint64_t getPipeIdx();

private:
	typedef enum {
		Free = 0,
		ReadFile,
		ReadFileResp,
		CreateFile,
		CreateFileResp,
		WriteFile,
		WriteWaitForReplica,
		CreateWaitForReplica,
		WriteFileResp,
		WriteReplicaReq,
		WriteReplicaReqResp,
		WriteReplica,
		WriteReplicaResp,
		CreateReplica,
		CreateReplicaReq,
		CreateReplicaResp,
		CreateReplicaReqResp,
		Done,
		Error,
		ErrorReplica,
	} TxState;

	typedef struct {
		WorkerTransaction *rtx;
	} ReplicaTx;

	TxState curState;

	Config *config;
	Worker *wrkr;
	unsigned pipe_id;

	FileIOCmd file_io_cmd;

	std::vector<ReplicaTx> in_flight_reps;
	WorkerTransaction *parent;
	uint64_t xaction_uuid;
	uint32_t num_replica_peers;
	uint32_t outstanding_io_ops;

	// State about the current transaction
	//std::string file_name;
	struct msg_header *hdr;
	std::vector<uint8_t> in_pkt;
	std::vector<uint8_t> out_pkt;

	std::recursive_mutex tx_lock;
	// Thread who puts tx in Done or Error state
        // is the one responsible to clean and free it.
	pthread_t finishing_thread_id;

	void allocateFileCmd(FileIOCmd::Cmd cmd);
	int submitReadIo();
	int submitWriteIo(bool create = false);
	int waitForReplica();
	int submitReplicaIoReq();
	int submitReplicaIo();
	int respondToReplicaIo();
	int respondToReadIo();
	int respondToWriteIo();
	int respondToReplicaIoReq();

	WorkerTransaction* createReplicaTx(int seq_num);
};

// Class that is the center point of all the various threaded entities and
// provides the coordination of the Acceptor and Filestore.
class Worker
{
public:

	// Default constructor/destructor
	Worker(Config *conf);
	~Worker();

	// callbacks for the various components
	void dispatch_incoming_request(WorkerTransaction *tx);
	void dispatch_incoming_replica_response(WorkerTransaction *tx);
	void dispatch_file_completion(WorkerTransaction *tx);

	void appendReplyToClient(WorkerTransaction *tx, unsigned id);
	void appendReplicaRequest(WorkerTransaction *tx, unsigned id);
	void submitFileIO(WorkerTransaction *tx);

private:
	// Pointer to a configuration object for the server
	Config *conf;
	Acceptor *listener;
	Acceptor *replica_listener;
	std::vector<Replicator*> replicators;
	FileIO *fileio;

	// Save both the fd and the sockio for debugging purposes for now
	int num_replica_peers;

	// May want a file descriptor cache here, but it just complicates the
	// code as it is.  Lets keep it simple for now.
	void setupReplicaConns();
};

#endif
