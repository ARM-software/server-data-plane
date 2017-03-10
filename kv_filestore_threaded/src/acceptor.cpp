/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _POSIX_SOURCE
#define _POSIX_C_SOURCE 201112L

#include "include/acceptor.hh"
#include "include/util.hh"

#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>

const static int MAX_BACKLOG = 1024;

/* Create the listening socket and the listener thread
 */
Acceptor::Acceptor(Config *_config,
		   Worker *_wrkr,
		   std::string _port,
		   std::string _interface)
	: config(_config), wrkr(_wrkr), sockfd(-1), port(_port), interface(_interface)

{
	struct addrinfo *ai;
	struct addrinfo hints = { .ai_flags = AI_PASSIVE,
				  .ai_family = AF_UNSPEC,
				  .ai_socktype = SOCK_STREAM };
	int error;
	int flags = 1;

	// Put port to some default value if it is not set
	if (port.empty()) {
		port = "0";
	}

	// Fill in the address info structure from kernel and with
	// info passed in by the user.
	if (interface.empty()) {
		error = getaddrinfo(nullptr, port.c_str(), &hints, &ai);
	} else {
		error = getaddrinfo(interface.c_str(), port.c_str(), &hints, &ai);
	}
	if (error != 0) {
		DEBUG_LOG("getaddrinfo(): %s\n", gai_strerror(error));
		std::string err = std::string("getaddrinfo(): ")
				  + std::string(gai_strerror(error)) +
				  std::string("\n");
		throw AcceptorException(err);
	}

	// Set up the socket
	sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sockfd == -1) {
		DEBUG_LOG("failed opening a listening socket.\n");
		throw AcceptorException("failed opening listening socket");
	}

	// Set up all the socket options for this socket descriptor
	error = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags,
			   sizeof(flags));
	if (error != 0)
		DEBUG_LOG("setsockopt error.\n");
	error = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags,
			     sizeof(flags));
	if (error != 0)
		DEBUG_LOG("setsockopt error.\n");
	error = setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (void *)&flags,
			   sizeof(flags));
	if (error != 0)
		DEBUG_LOG("setsockopt error.\n");
	error = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags,
			   sizeof(flags));
	if (error != 0)
		DEBUG_LOG("setsockopt error.\n");

	// bind() the socket, listen() and then setup the ODP structures
	error = bind(sockfd, ai->ai_addr, ai->ai_addrlen);
	if (error != 0) {
		DEBUG_LOG("bind error on socket.\n");
		throw AcceptorException("bind error on socket");
	}

	freeaddrinfo(ai);

	// Create listening thread
	try {
		thread = new AcceptorThread(this, config->getValue("core_mask"));
	} catch (AcceptorException &e) {
		close(sockfd);
		throw AcceptorException("listener thread failed");
	}

	// Create the reaper thread
	try {
		reaper = new ReaperThread(this, config->getValue("core_mask"));
	} catch (AcceptorException &e) {
		throw AcceptorException("reaper thread failed");
	}
}

Acceptor::~Acceptor()
{
	// Delete all our connections
	pipes_lock.lock();
	for (int i = 0; i < (int)pipes.size(); i++) {
		if (pipes[i] != nullptr) {
			delete pipes[i];
			pipes[i] = nullptr;
		}
	}
	pipes_lock.unlock();

	// Clean up our listening sockets
	delete thread;
	delete reaper;

	close(sockfd);
}

bool Acceptor::enqueueWrite(std::vector<uint8_t>&& buf, int pipe_id)
{
	if (pipes[pipe_id] != nullptr) {
		pipes[pipe_id]->enqueueWrite(std::move(buf));
		return true;
	}
	return false;
}

void Acceptor::enqueuePipeForReaping(unsigned id)
{
	reaper->enqueuePipe(id);
}

// Pass on to the central worker hub.
void Acceptor::dispatch_message(std::vector<uint8_t>&& buf, unsigned id)
{
	WorkerTransaction *tx = new WorkerTransaction(config, wrkr, id, std::move(buf));
	wrkr->dispatch_incoming_request(tx);
}

/* Create the thread and set it running to accept
 * incoming connections
 */
Acceptor::AcceptorThread::AcceptorThread(Acceptor *accept, std::string cpu_mask)
{
	a = accept;
	active = true;
	mask = cpu_mask;
	if (!create_thread(thread,
			   Acceptor::AcceptorThread::listen_trampoline,
			   (void*)this, mask)) {
		throw AcceptorException("could not create acceptor thread");
	}
}

Acceptor::AcceptorThread::~AcceptorThread()
{
	active = false;
	shutdown(a->sockfd, SHUT_RDWR);
	pthread_join(thread, nullptr);
}

/* Thread sits in an infinite loop waiting for incoming connections.
 * The socket is a blocking socket, so calls to accept will block
 * until a connection is available.
 */
void Acceptor::AcceptorThread::listen_for_incoming()
{
	int sfd = a->sockfd;
	int new_sfd = -1;

	int error = listen(sfd, MAX_BACKLOG);
	if (error != 0) {
		close(sfd);
		DEBUG_LOG("listen error on socket.\n");
		return;
	}

	while (active) {
		// Connect the input source or duplicate the UDP socket
		new_sfd = accept(sfd, NULL, NULL);
		if (new_sfd >= 0) {
			DEBUG_LOG("Accepted a connection\n");
			a->pipes_lock.lock();

			// Find an empty entry to place our pipe, or
			// create one if it does not exist.
			unsigned i = 0;
			for (i = 0; i < a->pipes.size(); i++) {
				if (a->pipes[i] == nullptr) {
					break;
				}
			}
			if (i == a->pipes.size()) {
				a->pipes.push_back(nullptr);
			}
			Pipe *newpipe = new Pipe(new_sfd, i, a, a->config);
			a->pipes[i] = newpipe;

			a->pipes_lock.unlock();
		} else {
			DEBUG_LOG("Accept returned, but not with a valid socket?\n");
			break;
		}
	}
	return;
}

void* Acceptor::AcceptorThread::listen_trampoline(void *arg)
{
	((Acceptor::AcceptorThread*)(arg))->listen_for_incoming();
	return nullptr;
}

Acceptor::ReaperThread::ReaperThread(Acceptor *accept, std::string cpu_mask)
{
	a = accept;
	active = true;
	mask = cpu_mask;
	if (!create_thread(thread, Acceptor::ReaperThread::reaper_trampoline,
			   (void*)this, mask)) {
		throw AcceptorException("could not create reaper thread");
	}
}

Acceptor::ReaperThread::~ReaperThread()
{
	active = false;
	cond.notify_all();
	pthread_join(thread, nullptr);
}

void* Acceptor::ReaperThread::reaper_trampoline(void *arg)
{
	((Acceptor::ReaperThread*)(arg))->reap_pipes();
	return nullptr;
}

void Acceptor::ReaperThread::reap_pipes()
{
	while (active) {
		std::unique_lock<std::mutex> lk(lock);
		while (!dead_pipes.empty()) {
			int idx = dead_pipes.front();
			dead_pipes.pop_front();

			a->pipes_lock.lock();
			// This exposes a race condition if we reap a pipe while
			// it still has outstanding transactions, they may try to
			// use this entry if it has been re-alloc'ed.  Not going to
			// worry about it now, but if this had to be a production
			// program, we would need to track outstanding transactions in
			// some fashion, or have a more robust method of identifying
			// comms channels.
			delete a->pipes[idx];
			a->pipes[idx] = nullptr;
			a->pipes_lock.unlock();
		}
		cond.wait(lk);
		//lk.unlock();
	}
}

void Acceptor::ReaperThread::enqueuePipe(int pipe_id)
{
	lock.lock();
	dead_pipes.push_back(pipe_id);
	lock.unlock();
	cond.notify_one();
}
