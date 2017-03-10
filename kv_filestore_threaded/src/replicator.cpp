/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "include/acceptor.hh"
#include "include/protocol.hh"
#include "include/util.hh"

#include <unistd.h>

const int MAX_RETRIES = 1024;

Replicator::Replicator(Worker *_wrkr, Config *config, std::string r_addr, std::string r_port)
{
	wrkr = _wrkr;
	conf = config;
	replica_target_addr = r_addr;
	replica_target_port = r_port;

	// Create replica connections out to other servers
	int threads = std::stoi(conf->getValue("threads"));
	int retries = 0;

	in_flight.resize(threads);
	seq_nums.resize(threads, 0);

	for (int i = 0; i < threads; i++) {
		shardedWQLocks[i].lock();
		int new_fd = createSocket(replica_target_addr,
					  replica_target_port);
		while (new_fd < 0) {
			// Looks like we have to wait
			sleep(1);
			retries++;
			if (retries >= MAX_RETRIES) {
				DEBUG_LOG("Can't contact replica server %s:%s.\n",
					  replica_target_addr.c_str(),
					  replica_target_port.c_str());
				throw AcceptorException("replica acceptor failed");
			}
			new_fd = createSocket(replica_target_addr,
					      replica_target_port);
		}

		Pipe *newpipe = new Pipe(new_fd, i, this, conf);
		shardedWQ.push_back(newpipe);
		shardedWQLocks[i].unlock();
	}
}

Replicator::~Replicator()
{
	for (unsigned i = 0; i < shardedWQ.size(); i++) {
		shardedWQLocks[i].lock();
		delete shardedWQ[i];
		shardedWQLocks[i].unlock();
	}
}

void Replicator::enqueuePipeForReaping(unsigned id)
{
	// Not sure I need to do anything here....
}

void Replicator::dispatch_message(std::vector<uint8_t>&& buf, unsigned id)
{
	struct msg_header *hdr = (struct msg_header*)buf.data();
	uint64_t xaction_uuid = ntohll(hdr->xaction_uuid);

	// Get the in flight tx
	shardedWQLocks[id].lock();
	WorkerTransaction *tx = in_flight[id][xaction_uuid];
	in_flight[id].erase(xaction_uuid);
	tx->setInPacket(std::move(buf));
	shardedWQLocks[id].unlock();

	wrkr->dispatch_incoming_replica_response(tx);
}

void Replicator::enqueueTx(WorkerTransaction *tx)
{
	// hash the incoming socket id
	unsigned idx = tx->getPipeIdx() % shardedWQ.size();

	shardedWQLocks[idx].lock();
	uint64_t uid = seq_nums[idx]++;
	uid = (uid << UUID_SHIFT) | tx->getTxUuid();
	tx->setReplicaReqUuid(uid);
	in_flight[idx][uid] = tx;
	shardedWQLocks[idx].unlock();

	shardedWQ[idx]->enqueueWrite(tx->getOutPacket());
}
