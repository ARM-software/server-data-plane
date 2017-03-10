/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <deque>

#include "include/exception.hh"
#include "include/worker.hh"

#ifndef FILEIO_HH
#define FILEIO_HH

class Worker;
class WorkerTransaction;

class FileIoException : public QdofsException
{
	using QdofsException::QdofsException;

	virtual const char* what() const throw()
	{
		std::string str = "FileIO exception: " + msg + "\n";
		return str.c_str();
	}
};

class FileIOCmd {
public:
	enum Cmd {
		Read = 0,
		Write = 1,
		Create = 2,
	};

	enum Res {
		InProgress = 0,
		Success = 1,
		Error = 2,
	};

	Cmd cmd;
	Res res;
	std::string filename;
	uint64_t file_offset;
	uint64_t file_op_len;
	std::vector<uint8_t> payload_buf;
};

class FileIO
{
public:
	FileIO(Worker *wrkr, Config *conf);
	~FileIO();

	void postFileCmd(WorkerTransaction *tx);
	void finishFileCmd(WorkerTransaction *tx);

private:
	class FileIOThread
	{
	public:
		FileIOThread(FileIO *file, std::string cpu_mask);
		~FileIOThread();

		void addTokens(unsigned tokens);
		void addTx(WorkerTransaction *tx);

	private:
		pthread_t thread;
		std::string mask;

		FileIO *f;
		volatile bool active;
		volatile unsigned credits;

		void wait_for_work();
		static void* fileio_trampoline(void *arg);

		std::mutex lock;
		std::condition_variable cond;
		std::deque<WorkerTransaction*> txs;
	};

	class TokenThread
	{
	public:
		TokenThread(FileIO *file, std::string cpu_mask);
		~TokenThread();

	private:
		void wait_for_tick();
		static void* token_trampoline(void *arg);

		pthread_t thread;
		std::string mask;
		unsigned tokens_per_tick;
		volatile bool active;

		FileIO *f;
	};

	void addTokens(unsigned tokens);

	TokenThread *token_thread;
	std::vector<FileIOThread*> file_threads;

	Worker *w;
	Config *c;
};

#endif
