/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp/helper/linux.h>
#include <odp/helper/strong_types.h>

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include "include/config.hh"
#include "include/worker.hh"

#include <cstdlib>
#include <cstdio>
#include <string>
#include <vector>

// This is not tunable at the moment.
static const int MAX_THREADS = 64;
odp_instance_t instance;

void printUsage()
{
	printf( "usage: qdofs port listen_port <replication servers: fqdn:port> [-options]\n"
		"       -c <core_mask: default 0xffffffffffffffff>\n"
		"       -d <storage directory>\n"
		"       -t <num_threads>\n"
		"       -v <work transaction pool size, default: 1048576>\n"
		"       -w <input packet size, default: 2048>\n"
		"       -x <output packet size, default: 2048>\n"
		"       -y <fileio_buf_size, default: 4096>\n"
		"       -z <transaction pool entries, default: 2048>\n"
		"       -h <print this help message>\n");
}

bool parseArgs(Config *config, int argc, char **argv)
{
	short c;

	// fill in default values.
	config->setValue("threads", std::string("1"));
	config->setValue("input_pkt_size", std::string("2048"));
	config->setValue("output_pkt_size", std::string("2048"));
	config->setValue("fileio_buf_size", std::string("4096"));
	config->setValue("pool_entries", std::string("2048"));
	config->setValue("worker_tx_pool_size", std::string("1048576"));
	config->setValue("core_mask", std::string("0xffffffffffffffff"));
	config->setValue("storage_directory", std::string(""));

	// parse optional arguments
	while ((c = getopt(argc, argv, "hc:d:t:v:w:x:y:z:")) != -1) {
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
		case 'v':
			config->setValue("worker_tx_pool_size", std::string(optarg));
			break;
		case 'w':
			config->setValue("input_pkt_size", std::string(optarg));
			break;
		case 'x':
			config->setValue("output_pkt_size", std::string(optarg));
			break;
		case 'y':
			config->setValue("fileio_buf_size", std::string(optarg));
			break;
		case 'z':
			config->setValue("pool_entries", std::string(optarg));
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

	// Initialize basic ODP structures here
	odp_pool_t input_pkt_pool;
	odp_pool_param_t input_pkt_pool_params;
	odp_pool_t output_pkt_pool;
	odp_pool_param_t output_pkt_pool_params;
	odp_pool_t fileio_pool;
	odp_pool_param_t fileio_pool_params;
	odp_pool_t fileio_cmd_pool;
	odp_pool_param_t fileio_cmd_pool_params;

	if (odp_init_global(&instance, NULL, NULL)) {
		DEBUG_LOG("Error: ODP global init failed.\n");
		exit(-1);
	}
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		DEBUG_LOG("Error: ODP local init failed.\n");
		exit(-1);
	}

	// Allocated the memory pools here
	input_pkt_pool_params.pkt.len = std::stoi(config.getValue("input_pkt_size"));
	input_pkt_pool_params.pkt.seg_len = std::stoi(config.getValue("input_pkt_size"));
	input_pkt_pool_params.pkt.num = std::stoi(config.getValue("pool_entries"));
	input_pkt_pool_params.type = ODP_EVENT_PACKET;
	input_pkt_pool = odp_pool_create("input_pkt_pool",
					 &input_pkt_pool_params);
	assert(input_pkt_pool != ODP_POOL_INVALID);

	output_pkt_pool_params.pkt.len = std::stoi(config.getValue("output_pkt_size"));
	output_pkt_pool_params.pkt.seg_len = std::stoi(config.getValue("output_pkt_size"));
	output_pkt_pool_params.pkt.num = std::stoi(config.getValue("pool_entries"));
	output_pkt_pool_params.type = ODP_EVENT_PACKET;
	output_pkt_pool = odp_pool_create("output_pkt_pool",
					  &output_pkt_pool_params);
	assert(output_pkt_pool != ODP_POOL_INVALID);

	fileio_pool_params.buf.size = std::stoi(config.getValue("fileio_buf_size"));
	fileio_pool_params.buf.num = std::stoi(config.getValue("pool_entries"));
	fileio_pool_params.buf.align = 0;
	fileio_pool_params.type = ODP_EVENT_BUFFER;
	fileio_pool = odp_pool_create("fileio_pool",
				      &fileio_pool_params);
	assert(fileio_pool != ODP_POOL_INVALID);

	fileio_cmd_pool_params.buf.size = sizeof(odp_fileio_cmd_t);
	fileio_cmd_pool_params.buf.num = std::stoi(config.getValue("pool_entries"));
	fileio_cmd_pool_params.buf.align = 0;
	fileio_cmd_pool_params.type = ODP_EVENT_BUFFER;
	fileio_cmd_pool = odp_pool_create("fileio_cmd_pool",
					  &fileio_cmd_pool_params);
	assert(fileio_cmd_pool != ODP_POOL_INVALID);

	// Insert the pool handles into the config object
	config.setValue("input_pkt_pool",
			std::to_string(_odph_typeval(input_pkt_pool)));
	config.setValue("output_pkt_pool",
			std::to_string(_odph_typeval(output_pkt_pool)));
	config.setValue("fileio_pool",
			std::to_string(_odph_typeval(fileio_pool)));
	config.setValue("fileio_cmd_pool",
			std::to_string(_odph_typeval(fileio_cmd_pool)));
	///////////////////////////////////////

	// Create threads and then wait for
	// them to finish.
	int threads = std::stoi(config.getValue("threads"));

	// Setup the ODP File IO handling
	odp_fileio_params_t fio_params;
	fio_params.type = ODP_FILEIO_SEPERATE_QUEUES; //ODP_FILEIO_STRICT_ORDER;
	fio_params.num_queues = threads;
	fio_params.cq_prio = ODP_SCHED_PRIO_NORMAL;
	if (odp_fileio_setup(fio_params) < 0) {
		DEBUG_LOG("Could not setup odp fileio!\n");
		return -1;
	}
	/////////////////////////////////

	// Create initial listening socket and replica listening socket
	// Similar to the way Ceph is setup.
	odp_sockio_t listener =
		odp_sockio_create_listener(std::stoi(config.getValue("listen_port")), NULL);
	assert(listener != ODP_SOCKIO_INVALID);
	odp_sockio_t replica_listener =
		odp_sockio_create_listener(std::stoi(config.getValue("replica_listen_port")), NULL);
	assert(replica_listener != ODP_SOCKIO_INVALID);
	// By this point, we have an open socket ready to accept
	// connections through the scheduler and let worker
	// threads handle the incoming connection requests.

	// ODP create threads and pin
	cpu_set_t mask;
	odp_cpumask_t pthread_mask;
	odp_cpumask_t cpu_mask;
	odp_cpumask_t zero_mask;
	odp_cpumask_zero(&zero_mask);

	odph_linux_pthread_t thread_tbl[MAX_THREADS];

	DEBUG_LOG("%s\n", config.getValue("core_mask").c_str());
	if (config.getValue("core_mask").compare("0xffffffffffffffff") == 0) {
		sched_getaffinity(0, sizeof(cpu_set_t), &(mask));
		odp_cpumask_from_cpuset(&pthread_mask, &mask);
	} else {
		odp_cpumask_t system_mask;
		odp_cpumask_t dst1;
		sched_getaffinity(0, sizeof(cpu_set_t), &(mask));
		odp_cpumask_from_cpuset(&system_mask, &mask);
		odp_cpumask_from_str(&pthread_mask,
				     config.getValue("core_mask").c_str());
		odp_cpumask_or(&dst1, &system_mask, &pthread_mask);
		if (!odp_cpumask_equal(&dst1, &system_mask)) {
			DEBUG_LOG("Entered Core Mask cannot be satisfied by system!\n");
			return -1;
		}
	}

	// Create the appropriate cpu mask for creating the threads
	int cpu = odp_cpumask_first(&pthread_mask);
	odp_cpumask_zero(&cpu_mask);
	printf("Creating %d workers\n", threads);
	for (int i = 0; i < threads; i++) {
		odp_cpumask_set(&cpu_mask, cpu);
		cpu = odp_cpumask_next(&pthread_mask, cpu);
	}

	odph_linux_thr_params_t thr_params;
	thr_params.start = Worker::WorkerStart;
	thr_params.arg = (void*)&config;
	thr_params.instance = instance;
	thr_params.thr_type = ODP_THREAD_IO_WORKER;

	int ret = odph_linux_pthread_create(thread_tbl, &cpu_mask, &thr_params);

	if (ret <= 0) {
		DEBUG_LOG("Creating threads failed!\n");
		return -1;
	}

	// Wait for the threads to join
	odph_linux_pthread_join(thread_tbl, threads);

	// terminate ODP
	if (odp_term_global(instance) < 0) {
		DEBUG_LOG("Failed to shutdown ODP on exit!\n");
		return -1;
	}

	return 0;
}
