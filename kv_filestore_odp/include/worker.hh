/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef WORKER_HH
#define WORKER_HH

#include <odp.h>
#include <map>
#include "include/protocol.hh"
#include "include/objpool.hh"
#include "include/util.hh"

// These are the same for now ... but in something more complicated, like
// full blown Ceph or Lustre, your peers may be all nodes, but you only
// replicate to a handful.
#define MAX_PEERS 16
#define MAX_REPLICAS 16

class Worker;

// This holds the state of each transaction as events
// come in from ODP to process them.
class WorkerTransaction : public object
{
public:
	WorkerTransaction();
	WorkerTransaction(uint64_t myHandle);
	WorkerTransaction(Config *config, Worker *wrkr, odp_event_t evt);
	~WorkerTransaction() {}

	// Run the transaction state machine
	int runStateMachine(odp_event_t evt);
	bool isDone()
	{
		if (curState == Done) return true;
		else return false;
	}
	bool isError()
	{
		if (curState == Error) return true;
		else return false;
	}

	int txFinishedBy()
	{
		return finishing_thread_id;
	}

	void initialize(Config *config, Worker *wrkr, odp_event_t evt);
	void initializeHandle(uint64_t handle);
	uint64_t getHandle();
	void setParent(WorkerTransaction *parent);
	WorkerTransaction* getParent();
	void notifyParent(int idx);
	void cleanObject();
	int getState();
	int sendErrorToClient(odp_event_t evt);

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
		Error
	} TxState;

	typedef struct {
		WorkerTransaction *rtx;
		odp_event_t req;
	} ReplicaTx;

	TxState curState;

	Config *config;
	Worker *wrkr;

	// This is the event that spawned this object
	odp_event_t client_evt;
	// ODP state to keep track of potentially while the event is in flight
	odp_pool_t fileio_pool;
	odp_pool_t output_pkt_pool;
	odp_pool_t fileio_cmd_pool;

	odp_event_t fileio_cmd;
	odp_fileio_cmd_t *cmd;
	odp_buffer_t file_buffer;
	uint64_t my_uuid; // This is a handle representation of the object.
	                  // It will allow us to find it later when packet acks
			  // return.
	ReplicaTx in_flight_reps[MAX_REPLICAS];
	WorkerTransaction *parent;
	uint64_t xaction_uuid;
	int num_replica_peers;
	odp_atomic_u32_t outstanding_io_ops;

	// State about the current transaction
	std::string file_name;
	int op_fd;
	struct msg_header *hdr;

	std::recursive_mutex tx_lock;
	// Thread who puts tx in Done or Error state
        // is the one responsible to clean and free it.
	int finishing_thread_id;

	int allocateFileCmd(odp_event_t evt);
	int submitReadIo(odp_event_t evt);
	int submitWriteIo(odp_event_t evt, bool create = false);
	int waitForReplica(odp_event_t evt);
	int submitReplicaIoReq(odp_event_t evt);
	int submitReplicaIo(odp_event_t evt);
	int respondToReplicaIo(odp_event_t evt);
	int respondToReadIo(odp_event_t evt);
	int respondToWriteIo(odp_event_t evt);
	int respondToReplicaIoReq(odp_event_t evt);

	odp_event_t createReplicaEvent(WorkerTransaction *rtx, int seq_num);
};

// Class that encapsulates an ODP worker thread
class Worker
{
public:
	// Factory method that creates the worker
	// and initializes it inside the thread.
	static void* WorkerStart(void *arg);

	// Default constructor/destructor
	Worker(Config *conf);
	~Worker() {}

	int sendReplicaRequest(odp_event_t evt, int replica_num);
	WorkerTransaction* allocateTxObj()
	{
		return objPool->allocateObj();
	}
	void freeObj(WorkerTransaction* tx)
	{
		objPool->freeObj(tx);
	}

private:
	// Pointer to a configuration object for the server
	Config *conf;
	odp_pool_t input_pkt_pool;

	// Pull worker transactions from here
	ObjPool<WorkerTransaction> *objPool;

	// Save both the fd and the sockio for debugging purposes for now
	int replica_sfds[MAX_PEERS];
	odp_sockio_t replica_sockios[MAX_PEERS];
	int num_replica_peers;

	// May want a file descriptor cache here, but it just complicates the
	// code as it is.  Lets keep it simple for now.

	// Event loop function that runs the odp_schedule() code
	void processEvents();
	void processConnectionEvent(odp_event_t c_evt);
	void processRequest(odp_event_t evt);
	void processFileCompl(odp_event_t evt);
	void setupReplicaConns();
};

#endif
