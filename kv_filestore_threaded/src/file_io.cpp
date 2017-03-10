/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "include/file_io.hh"
#include "include/util.hh"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Same constraints as the ODP version, 4MB of outstanding IO allowed 
// per milli-second to throttle the IO. Ceph also has an IO throttler.
const uint64_t bytesPerToken = 4096;
const uint64_t tokensPerQueue = 1024;
const uint64_t maxTokensPerQueue = 2048;

FileIO::FileIO(Worker *wrkr, Config *conf)
{
	w = wrkr;
	c = conf;

	int threads = std::stoi(conf->getValue("threads"));
	std::string core_mask = conf->getValue("core_mask");

	for (int i = 0; i < threads; i++) {
		FileIOThread *thread = nullptr;
		try {
			thread = new FileIOThread(this, core_mask);
			file_threads.push_back(thread);
		} catch (...) {
			throw FileIoException("failed to start all IO thread resources");
		}
	}

	try {
		token_thread = new TokenThread(this, core_mask);
	} catch (...) {
		throw FileIoException("failed to start token thread resources");
	}

}

FileIO::~FileIO()
{
	for (unsigned i = 0; i < file_threads.size(); i++) {
		delete file_threads[i];
	}
	delete token_thread;
}

void FileIO::postFileCmd(WorkerTransaction *tx)
{
	uint64_t hash = hashString(tx->getFileOp().filename);
	file_threads[hash % file_threads.size()]->addTx(tx);
}

void FileIO::finishFileCmd(WorkerTransaction *tx)
{
	w->dispatch_file_completion(tx);
}

void FileIO::addTokens(unsigned tokens)
{
	for (unsigned i = 0; i < file_threads.size(); i++) {
		file_threads[i]->addTokens(tokens);
	}
}

FileIO::FileIOThread::FileIOThread(FileIO *file, std::string cpu_mask)
{
	mask = cpu_mask;
	f = file;

	active = true;
	credits = tokensPerQueue;

	if (!create_thread(thread, FileIO::FileIOThread::fileio_trampoline,
			   (void*)this, mask)) {
	    throw FileIoException("could not create file io thread");
	}
}

FileIO::FileIOThread::~FileIOThread()
{
	active = false;
	cond.notify_all();
	pthread_join(thread, nullptr);
	txs.clear();
}

void FileIO::FileIOThread::addTokens(unsigned tokens)
{
	std::unique_lock<std::mutex> lk(lock);

	credits += tokens;
	if (credits > maxTokensPerQueue) credits = maxTokensPerQueue;
}

void FileIO::FileIOThread::addTx(WorkerTransaction *tx)
{
	{
		std::unique_lock<std::mutex> lk(lock);
		txs.push_back(tx);
	}
	cond.notify_all();
}

void FileIO::FileIOThread::wait_for_work()
{
	while (active) {
		std::unique_lock<std::mutex> lk(lock);
		//lock.lock();
		while (!txs.empty() && credits) {
			WorkerTransaction *tx = txs.front();
			txs.pop_front();

			FileIOCmd& cmd = tx->getFileOp();

			// Figure out if we have the credits needed
			uint32_t tokens = cmd.file_op_len / bytesPerToken;
			if (tokens == 0) tokens = 1;

			if (tokens < credits) {
				credits -= tokens;
			} else {
				break;
			}

			if (cmd.cmd == FileIOCmd::Cmd::Read) {
				cmd.payload_buf.resize(cmd.file_op_len);
				uint8_t *data = cmd.payload_buf.data();

				int fd = open(cmd.filename.c_str(), O_RDONLY);
				struct stat buf;

				if (fd < 0) {
					DEBUG_LOG("Could not open file %s-%d for reading! Dropping request.\n",
						  cmd.filename.c_str(), errno);
					cmd.res = FileIOCmd::Res::Error;
				} else {
					// truncate requests that are longer
					// than the file is.
					if (fstat(fd, &buf) < 0) {
						DEBUG_LOG("Could not stat file %s errno: %d!\n",
							  cmd.filename.c_str(),
							  errno);
						cmd.res = FileIOCmd::Res::Error;
					} else {
						if ((unsigned)buf.st_size < cmd.file_op_len) {
							cmd.file_op_len = buf.st_size;
						}

						int bytes = 0;
						while ((unsigned)bytes < cmd.file_op_len) {
							int res = pread(fd, data+bytes,
									cmd.file_op_len - bytes,
									bytes);
							if (res > 0) {
								bytes += res;
							} else if (res == 0) {
							break;
							} else {
								DEBUG_LOG("file read errored %s-%d\n", 
									  cmd.filename.c_str(), errno);
								cmd.res = FileIOCmd::Res::Error;
								break;
							}
						}
					}
					close(fd);
				}
			} else if (cmd.cmd == FileIOCmd::Cmd::Write ||
				   cmd.cmd == FileIOCmd::Cmd::Create) {
				uint8_t *data = cmd.payload_buf.data();

				int flags = (cmd.cmd == FileIOCmd::Cmd::Create) ?
					O_WRONLY | O_CREAT : O_WRONLY;

				int fd = open(cmd.filename.c_str(), flags,
					      S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
				if (fd < 0) {
					DEBUG_LOG("Could not open file %s-%d for writing! Dropping request.\n",
						  cmd.filename.c_str(), errno);
					cmd.res = FileIOCmd::Res::Error;
				} else {
					int bytes = 0;
					while ((unsigned)bytes < cmd.file_op_len) {
						int res = pwrite(fd, data+bytes,
								 cmd.file_op_len - bytes,
								 bytes);
						if (res > 0) {
							bytes += res;
						} else if (res == 0) {
							break;
						} else {
							DEBUG_LOG("file write errored %s-%d\n",
								  cmd.filename.c_str(), errno);
							cmd.res = FileIOCmd::Res::Error;
							break;
						}
					}
					close(fd);
				}
			} else {
				DEBUG_LOG("Got a corrupt file cmd!\n");
			}

			cmd.res = FileIOCmd::Res::Success;
			f->finishFileCmd(tx);
		}
		//lock.unlock();
		//std::unique_lock<std::mutex> lk(lock);
		cond.wait(lk);
	}
}

void* FileIO::FileIOThread::fileio_trampoline(void *arg)
{
	((FileIO::FileIOThread*)arg)->wait_for_work();
	return nullptr;
}

FileIO::TokenThread::TokenThread(FileIO *file, std::string cpu_mask)
{
	mask = cpu_mask;
	f = file;

	active = true;
	tokens_per_tick = tokensPerQueue;

	if (!create_thread(thread, FileIO::TokenThread::token_trampoline,
			   (void*)this, mask)) {
	    throw FileIoException("could not create token thread");
	}

}

FileIO::TokenThread::~TokenThread()
{
	active = false;
	pthread_join(thread, nullptr);
}

void FileIO::TokenThread::wait_for_tick()
{
	struct timespec t = {0, 1000000};
	struct timespec rem = {0, 0};

	while (active) {
		if (nanosleep(&t, &rem)) {
			t.tv_nsec = rem.tv_nsec;
		} else {
			t.tv_nsec = 1000000;
			f->addTokens(tokens_per_tick);
		}
	}
}

void* FileIO::TokenThread::token_trampoline(void *arg)
{
	((FileIO::TokenThread*)arg)->wait_for_tick();
	return nullptr;
}
