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

#include "include/acceptor.hh"
#include "include/config.hh"
#include "include/protocol.hh"
#include "include/worker.hh"
#include "include/util.hh"

static const int MAX_RETRIES = 4096;

Worker::Worker(Config *_conf)
{
	conf = _conf;

	// Setup file IO.
	fileio = new FileIO(this, conf);

	try {
		listener = new Acceptor(conf, this, conf->getValue("listen_port"), "");
		replica_listener = new Acceptor(conf, this, conf->getValue("replica_listen_port"), "");
	} catch (...) {
		throw WorkerException("failed to create listeners");
	}

	setupReplicaConns();
}

Worker::~Worker()
{
	delete fileio;
	delete listener;
	delete replica_listener;

	for (int i = 0; i < num_replica_peers; i++) {
		delete replicators[i];
	}
}

// Make connections to the replica servers, will have to use timeouts here and
// max retries in case something just blows up.
void Worker::setupReplicaConns()
{
	num_replica_peers = std::stoi(conf->getValue("numReplicas"));

	for (int i = 0; i < num_replica_peers; i++) {
		std::string addr_key = "replica-" + std::to_string(i) + "-addr";
		std::string port_key = "replica-" + std::to_string(i) + "-port";
		std::string addr = conf->getValue(addr_key);
		std::string port = conf->getValue(port_key);

		Replicator *rep = new Replicator(this, conf, addr, port);
		replicators.push_back(rep);
	}
}

void Worker::dispatch_incoming_request(WorkerTransaction *tx)
{
	tx->runStateMachine();

	if (tx->isDone() && 
	    pthread_equal(pthread_self(), tx->txFinishedBy())) {
		delete tx;
	} else if (tx->isError() && 
		   pthread_equal(pthread_self(),tx->txFinishedBy())) {
		tx->sendErrorToClient();
		delete tx;
	}
}

void Worker::dispatch_incoming_replica_response(WorkerTransaction *tx)
{
	WorkerTransaction *ptx = tx->getParent();

	assert(tx != nullptr);
	assert(ptx != nullptr);

	tx->runStateMachine();
	ptx->runStateMachine();

	// The replica TX is no longer live here
	if (tx->isError()) {
		throw WorkerException("Replica failed");
	}
	// Doesn't matter if it succeeds, it is done.
	delete tx;

	if (ptx->isDone() &&
	    pthread_equal(pthread_self(), ptx->txFinishedBy())) {
		delete ptx;
	} else if (ptx->isError() &&
		   pthread_equal(pthread_self(), ptx->txFinishedBy())) {
		ptx->sendErrorToClient();
		delete ptx;
	}
}

void Worker::dispatch_file_completion(WorkerTransaction *tx)
{
	tx->runStateMachine();

	if (tx->isDone() &&
	    pthread_equal(pthread_self(), tx->txFinishedBy())) {
		delete tx;
	} else if (tx->isError() &&
		   pthread_equal(pthread_self(), tx->txFinishedBy())) {
		// If we error, it is unrecoverable, drop tx and clean
		// up!
		tx->sendErrorToClient();
		delete tx;
	}
}

void Worker::appendReplyToClient(WorkerTransaction *tx, unsigned id)
{
	if (tx->isReplicaReq()) {
		replica_listener->enqueueWrite(std::move(tx->getOutPacket()),
					       tx->getPipeIdx());
	} else {
		listener->enqueueWrite(std::move(tx->getOutPacket()),
				       tx->getPipeIdx());
	}
}

void Worker::appendReplicaRequest(WorkerTransaction *tx, unsigned id)
{
	replicators[id]->enqueueTx(tx);
}

void Worker::submitFileIO(WorkerTransaction *tx)
{
	fileio->postFileCmd(tx);
}
