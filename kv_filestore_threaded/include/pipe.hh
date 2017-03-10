/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "include/config.hh"
#include "include/exception.hh"

#include <string>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <vector>

#include <pthread.h>

#ifndef PIPE_HH
#define PIPE_HH

class Messenger;

/* Basic exception for error handling pipes */
class PipeException : public QdofsException
{
	using QdofsException::QdofsException;

	virtual const char* what() const throw()
	{
		std::string str = "Pipe exception: " + msg + "\n";
		return str.c_str();
	}
};

/* This is meant to emulate what I read in the Ceph
 * Pipe definition.  1 thread for reading the socket, 
 * 1 for writing.  The Pipe will call directly into the
 * transaction parsing routines (only fast_dispatch in Ceph lingo)
 * when it gets a message. The packet parsing logic is embedded
 * directly into the pipe. For writing output, the pipe has an enqueue function.
 */
class Pipe
{
public:
	Pipe(int sock, unsigned id, Messenger *msgr, Config *config);
	~Pipe();

	void enqueueWrite(std::vector<uint8_t>&& buf);

private:
	class ReaderThread {
	public:
		ReaderThread(int sock, Messenger *msgr, Pipe *parent, std::string cpu_mask);
		~ReaderThread();

	private:
		pthread_t thread;
		std::string mask;
		Messenger *m;
		Pipe *p;
		// Worker pointer here too?
		int sockfd;
		volatile bool active;

		// Embeds basic message parsing before sending things along
		void reader();
		static void* reader_trampoline(void *arg);
	};

	class WriterThread {
	public:
		WriterThread(int sock, Messenger *msgr, Pipe *parent, std::string cpu_mask);
		~WriterThread();
		pthread_t getThread();
		void enqueueBuffer(std::vector<uint8_t>&& buf);

	private:
		pthread_t thread;
		std::string mask;
		Messenger *m;
		Pipe *p;
		// Worker pointer here too?
		int sockfd;
		std::deque<std::vector<uint8_t> > workQueue;
		std::mutex lock; // Protect the work queue
		std::condition_variable cond; // Sleep on an empty work queue
		volatile bool active;

		void writer();
		static void* writer_trampoline(void *arg);
	};

	void reportPipeClose();
	void dispatch_message(std::vector<uint8_t>&& buf);

	ReaderThread *reader;
	WriterThread *writer;
	Messenger *m;
	Config *conf;
	// Also include a pointer to the main "OSD" object to process messages
	// in this thread, and pass to next thread. 
	int sockfd;
	unsigned id;
	volatile bool closed;
};

#endif
