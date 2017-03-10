/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#include <cstdlib>
#include <string>

#include "include/util.hh"

int createSocket(std::string addr, std::string port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	ret = getaddrinfo(addr.c_str(), port.c_str(), &hints, &result);
	if (ret != 0) {
		printf("getaddrinfo: %s for address %s:%s\n", gai_strerror(ret),
		       addr.c_str(), port.c_str());
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) {
			continue;
		}
		ret = connect(sfd, rp->ai_addr, rp->ai_addrlen);
		if (ret == 0) {
			break;
		}
		close(sfd);
		sfd = -1;
	}
	return sfd;
}

bool create_thread(pthread_t &thread, void *(*start_routine)(void *), 
		   void *arg, std::string cpu_mask)
{
	// Create thread and pin to core region
	pthread_attr_t attr;

	cpu_set_t pthread_mask;
	CPU_ZERO(&pthread_mask);

	DEBUG_LOG("%s\n", cpu_mask.c_str());
	if (cpu_mask.compare("0xffffffffffffffff") == 0) {
		sched_getaffinity(0, sizeof(cpu_set_t), &pthread_mask);
	} else {
		cpu_set_t system_mask;
		cpu_set_t dst1;
		sched_getaffinity(0, sizeof(cpu_set_t), &system_mask);
		cpumask_from_str(pthread_mask, cpu_mask);
		CPU_OR(&dst1, &system_mask, &pthread_mask);
		if (!CPU_EQUAL(&dst1, &system_mask)) {
			DEBUG_LOG("Entered Core Mask %s cannot be satisfied by system!\n",
				  cpu_mask.c_str());
			return false;
		}
	}

	pthread_attr_init(&attr);
	if (pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t),
				     &pthread_mask)) {
	       DEBUG_LOG("Error trying to set thread affinity!\n");
	       return false;
	}
	if (pthread_create(&thread, &attr, start_routine, arg)) {
		DEBUG_LOG("Error trying to create thread!\n");
		return false;
	}
	return true;
}

void cpumask_from_str(cpu_set_t &mask, std::string str)
{
	size_t pos;
	int cpu = 0;

	// Strip out 0x or 0X first
	pos = str.find("0X");
	if (pos != std::string::npos) {
		str = str.erase(pos, 2);
	}
	pos = str.find("0x");
	if (pos != std::string::npos) {
		str = str.erase(pos, 2);
	}

	CPU_ZERO(&mask);

	// loop through the string from the back to front
	for (auto rbegin = str.rbegin(); rbegin != str.rend(); rbegin++) {
		char c = *rbegin;
		int value;
		int idx;

		if ((c >= '0') && (c <= '9')) {
			value = c - '0';
		} else if ((c >= 'A') && (c <= 'F')) {
			value = c - 'A' + 10;
		} else if ((c >= 'a') && (c <= 'f')) {
			value = c - 'a' + 10;
		} else {
			return;
		}

		for (idx = 0; idx < 4; idx++, cpu++) {
			if (value & (1 << idx)) {
				CPU_SET(cpu, &mask);
			}
		}

	}

}

int cpumask_first(cpu_set_t mask)
{
	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &mask)) {
			return cpu;
		}
	}
	return -1;
}

int cpumask_next(cpu_set_t mask, int cpu)
{
	for (cpu+=1; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &mask)) {
			return cpu;
		}
	}
	return -1;
}

uint64_t hashString(std::string str)
{
	uint64_t hash = 3074457345618258791ul;
	int len = str.size();
	for (int i = 0; i < len; i++) {
		hash += str[i];
		hash *= 2074457345618258799ul;
	}
	return hash;
}
