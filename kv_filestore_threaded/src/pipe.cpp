/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "include/util.hh"
#include "include/pipe.hh"
#include "include/protocol.hh"
#include "include/acceptor.hh"

#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

Pipe::Pipe(int sock, unsigned _id, Messenger *msgr, Config *config)
{
	sockfd = sock;
	m = msgr;
	conf = config;
	closed = false;
	id = _id;

	// Initialize whatever else I need to here, but
	// seems like nothing else is needed besides the glue
	// Worker class which is like the OSD class in Ceph.
	try {
		writer = new WriterThread(sockfd, m, this,
					 conf->getValue("core_mask"));
	} catch (PipeException &e) {
		// clean up, we're dead
		delete reader;
		if (close(sockfd) != 0) {
			DEBUG_LOG("Socket failed to close!?\n");
		}
		throw PipeException("failed to open write pipe thread");
	}

	try {
		reader = new ReaderThread(sockfd, m, this,
					  conf->getValue("core_mask"));
	} catch (PipeException &e) {
		// clean up, we're dead
		if (close(sockfd) != 0) {
			DEBUG_LOG("Socket failed to close!?\n");
		}
		throw PipeException("failed to open read pipe thread");
	}

}

Pipe::~Pipe()
{
	delete reader;
	delete writer;

	if (close(sockfd) != 0) {
		DEBUG_LOG("Failed to close pipe socket!?\n");
	}
}

void Pipe::enqueueWrite(std::vector<uint8_t>&& buf)
{
	writer->enqueueBuffer(std::move(buf));
	// Could collect stats or something here...
}

// Pass through...
void Pipe::dispatch_message(std::vector<uint8_t>&& buf)
{
	m->dispatch_message(std::move(buf), id);
}

Pipe::ReaderThread::ReaderThread(int sock, Messenger *msgr,
				 Pipe *parent, std::string cpu_mask)
{
	sockfd = sock;
	mask = cpu_mask;
	m = msgr;
	p = parent;
	active = true;

	if (!create_thread(thread, Pipe::ReaderThread::reader_trampoline,
			   (void*)this, mask)) {
		throw PipeException("could not create thread");
	}
}

Pipe::ReaderThread::~ReaderThread()
{
	// clean up by shutting down the socket and
	// waiting for the thread to join
	active = false;
	shutdown(sockfd, SHUT_RD);
	pthread_join(thread, nullptr);
}

void* Pipe::ReaderThread::reader_trampoline(void *arg)
{
	((Pipe::ReaderThread*)arg)->reader();
	return nullptr;
}

void Pipe::ReaderThread::reader()
{
	// XXX: Just return immediately for now.
	// Readerthread can report a socket has errored and needs
	// to close.
	while (active) {
		// Start reading in the header
		struct msg_header tmp;
		unsigned bytes = 0;

		while (bytes < sizeof(msg_header)) {
			int ret = recv(sockfd, ((char*)(&tmp) + bytes),
				       sizeof(msg_header) - bytes, 0);
			if (ret > 0) {
				bytes += ret;
			} else {
				DEBUG_LOG("Error on recv for socket %d,%d\n",
					  sockfd, errno);
				goto exit;
			}
		}

		// Error check the header
		if (tmp.magic != MAGIC_NUM && tmp.magic != MAGIC_NUM_RESP) {
			DEBUG_LOG("Got a corrupt packet on socket: %d\n", sockfd);
			goto exit;
		}

		// Read in the full buffer
		bytes = 0;
		std::vector<uint8_t> buf(ntohl(tmp.total_payload) + sizeof(tmp));
		uint8_t *data = buf.data();
		memcpy(data, &tmp, sizeof(tmp));
		data += sizeof(tmp);

		unsigned payload = ntohl(tmp.total_payload);

		while (bytes < payload) {
			int ret = recv(sockfd, data + bytes,
				       payload - bytes, 0);

			if ( ret > 0) {
				bytes += ret;
			} else {
				DEBUG_LOG("Error on recv for socket %d,%d\n",
					  sockfd, errno);
				goto exit;
			}
		}

		// dispatch the message here.
		// DEBUG_LOG("Dispatch recv'ed packet of %dB\n", payload);
		p->dispatch_message(std::move(buf));
	}
exit:
	// Tell reaper thread we are shutting down.
	p->reportPipeClose();
	return;
}

Pipe::WriterThread::WriterThread(int sock, Messenger *msgr, Pipe *parent,
				 std::string cpu_mask)
{
	sockfd = sock;
	mask = cpu_mask;
	m = msgr;
	p = parent;
	active = true;

	if (!create_thread(thread, Pipe::WriterThread::writer_trampoline,
			   (void*)this, mask)) {
		throw PipeException("could not create thread");
	}
}

Pipe::WriterThread::~WriterThread()
{
	active = false;
	shutdown(sockfd, SHUT_WR);
	cond.notify_all();
	pthread_join(thread, nullptr);
	workQueue.clear();
}

void* Pipe::WriterThread::writer_trampoline(void *arg)
{
	((Pipe::WriterThread*)arg)->writer();
	return nullptr;
}

void Pipe::WriterThread::writer()
{
	// XXX: Just return immediately for now
	// Writerthread does not report socket errors as it will
	// just wait on the condition variable if something fails
	while (active) {
		std::unique_lock<std::mutex> lk(lock);
		while (!workQueue.empty()) {
			std::vector<uint8_t> buf = workQueue.front();
			workQueue.pop_front();

#ifdef DEBUG
			DEBUG_LOG("Writing to socket %d\n", sockfd);
#endif
			uint8_t* buffer = buf.data();

			unsigned bytes = 0;
			while (bytes < buf.size()) {
				int ret = send(sockfd, buffer + bytes, buf.size() -
					       bytes, 0);
				if (ret >= 0) {
					bytes += ret;
				} else {
					DEBUG_LOG("A write failed on socket %d,%d\n", sockfd, errno);
					active = false;
					break;
				}
			}

		}
		cond.wait(lk);
	}
}

// Post a write to the workqueue
void Pipe::WriterThread::enqueueBuffer(std::vector<uint8_t>&& buf)
{
	lock.lock();
	workQueue.push_back(std::move(buf));
	lock.unlock();
	cond.notify_all();
}

void Pipe::reportPipeClose()
{
	closed = true;
	// Call reaper thread in acceptor (which is like the messenger in Ceph)
	m->enqueuePipeForReaping(id);
}
