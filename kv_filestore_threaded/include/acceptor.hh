/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "include/config.hh"
#include "include/exception.hh"
#include "include/pipe.hh"
#include "include/worker.hh"

#include <array>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <vector>

#include <pthread.h>

#ifndef ACCEPTOR_HH
#define ACCEPTOR_HH

#define MAX_REPLICATORS 32

class Worker;
class WorkerTransaction;

/* Basic exception for error handling acceptors in the program */
class AcceptorException : public QdofsException
{
	using QdofsException::QdofsException;

	virtual const char* what() const throw ()
	{
		std::string str = "Acceptor exception: " + msg + "\n";
		return str.c_str();
	}
};

/* Base class interface for Pipes to plug
 * into so they can notify the messenger they
 * have closed.
 */
class Messenger {
public:
	Messenger() {}
	virtual ~Messenger() {}

	virtual void enqueuePipeForReaping(unsigned int) = 0;
	virtual void dispatch_message(std::vector<uint8_t>&& buf, unsigned id) = 0;
};

/* This class creates a thread that sits
 * and waits for new connections.  For each
 * new connection it creates a Pipe.
 */
class Acceptor : public Messenger {
public:
	Acceptor(Config *config, Worker *wrkr, std::string port,
		 std::string interface);
	~Acceptor();
	bool enqueueWrite(std::vector<uint8_t>&& buf, int pipe_id);

	virtual void enqueuePipeForReaping(unsigned int);
	virtual void dispatch_message(std::vector<uint8_t>&& buf, unsigned id);

private:
	class AcceptorThread {
	public:
		AcceptorThread(Acceptor *accept, std::string cpu_mask);
		~AcceptorThread();

	private:
		pthread_t thread;
		std::string mask;
		Acceptor *a;
		volatile bool active;

		void listen_for_incoming();
		static void* listen_trampoline(void *arg);
	};

	class ReaperThread {
	public:
		ReaperThread(Acceptor *accept, std::string cpu_mask);
		~ReaperThread();

		void enqueuePipe(int pipe_idx);
	private:
		pthread_t thread;
		std::string mask;
		std::deque<int> dead_pipes;
		Acceptor *a;
		std::mutex lock;
		std::condition_variable cond;
		volatile bool active;

		void reap_pipes();
		static void* reaper_trampoline(void *arg);
	};

	AcceptorThread *thread;
	ReaperThread *reaper;
	Config *config;
	Worker *wrkr;
	int sockfd;
	std::string port;
	std::string interface;
	std::vector<Pipe*> pipes;
	std::mutex pipes_lock;
};

class Replicator : public Messenger
{
public:
	Replicator(Worker *wrkr, Config *conf, 
		   std::string r_addr, std::string r_port);
	~Replicator();

	virtual void enqueuePipeForReaping(unsigned id);
	// Call back from the pipe threads to construct a message to send
	// onwards
	void dispatch_message(std::vector<uint8_t>&& buf, unsigned id);
	void enqueueTx(WorkerTransaction *tx);

private:
	Worker *wrkr;
	Config *conf;
	std::string replica_target_addr;
	std::string replica_target_port;

	// State to track transactions that are being replicated by remote
	// servers
	std::vector<Pipe*> shardedWQ;
	std::array<std::mutex, MAX_REPLICATORS> shardedWQLocks;
	std::vector<std::map<uint64_t, WorkerTransaction*> > in_flight;
	std::vector<uint64_t> seq_nums;
	std::mutex lock;
};

#endif
