/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>

#include "include/acceptor.hh"
#include "include/config.hh"
#include "include/worker.hh"

#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <string>
#include <vector>

static volatile bool program_active = true;

void printUsage()
{
	printf( "usage: qdofs port listen_port <replication servers: fqdn:port> [-options]\n"
		"       -c <core_mask: default 0xffffffffffffffff>\n"
		"       -d <storage directory>\n"
		"       -t <num_storage_threads>\n"
		"       -h <print this help message>\n");
}

bool parseArgs(Config *config, int argc, char **argv)
{
	short c;

	// fill in default values.
	config->setValue("threads", std::string("1"));
	config->setValue("core_mask", std::string("0xffffffffffffffff"));
	config->setValue("storage_directory", std::string(""));

	// parse optional arguments
	while ((c = getopt(argc, argv, "hc:d:t:")) != -1) {
		switch(c) {
		case 'h':
			printUsage();
			return false;
			break;
		case 'c':
			config->setValue("core_mask", std::string(optarg));
			break;
		case 'd':
			config->setValue("storage_directory",
					 std::string(optarg));
			break;
		case 't':
			config->setValue("threads", std::string(optarg));
			break;
		default:
			break;
		}

	}

	// parse positional arguments
	if ((argc - optind) < 2) {
		printUsage();
		return false;
	}
	std::string listen_port = argv[optind];
	std::string replica_listen_port = argv[optind + 1];

	int num_replica_servers = 0;
	// Implement replica servers later
	for (int i = optind + 2; i < argc; i++) {
		std::string replica_server = argv[i];
		if (replica_server == "") {
			// Ignore empry input args
			continue;
		}
		size_t idx = replica_server.find(":");
		std::string replica_server_addr = replica_server.substr(0, idx);
		std::string replica_server_port = replica_server.substr(idx+1,
									replica_server.size() - idx - 1);
		std::string tmp1 = "replica-" + std::to_string(i - optind - 2) + "-addr";
		std::string tmp2 = "replica-" + std::to_string(i - optind - 2) + "-port";
		config->setValue(tmp1, replica_server_addr);
		config->setValue(tmp2, replica_server_port);
		num_replica_servers++;
	}
	config->setValue("numReplicas", std::to_string(num_replica_servers));
	config->setValue("listen_port", listen_port);
	config->setValue("replica_listen_port", replica_listen_port);

	return true;
}

void program_exit_handler(int signal)
{
	program_active = false;
}

int main(int argc, char **argv)
{
	// Start by parsing our arguments
	// <prog> <listen port> <num threads> <replicate server 1>
	// ... <replicate server n as hostname:port or IP:port>
	Config config;
	if (!parseArgs(&config, argc, argv)) {
		return -1;
	}

	// Set up our current working directory, this way we store files in the
	// proper location.
	if (config.getValue("storage_directory").size() > 0) {
		if (chdir(config.getValue("storage_directory").c_str()) < 0) {
			DEBUG_LOG("Error: could not change cwd to %s,%d\n",
				  config.getValue("storage_directory").c_str(), errno);
			return -1;
		}
	}

	// Create initial listening socket and replica listening socket
	// Similar to the way Ceph is setup.
	Worker *wrk;
	try {
		wrk = new Worker(&config);
	} catch (WorkerException &e) {
		DEBUG_LOG("Failed to create the main worker!\n");
		return -1;
	}

	// wait for the program to exit by waiting for a SIGINT
#ifdef DEBUG
	while (1) {
		sleep(1000);
	}
#else
	std::signal(SIGINT, program_exit_handler);
	sigset_t sigset;
	int sig;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (sigwait(&sigset, &sig) == 0) {
		DEBUG_LOG("Program exiting!\n");
	}
#endif

	// clean up
	DEBUG_LOG("Clean-up our resources!\n");
	//delete wrk;

	return 0;
}
