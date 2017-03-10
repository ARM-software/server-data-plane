/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef UTIL_HH
#define UTIL_HH

#include <string>
#include <cstdio>
#include <cstdlib>

#include <pthread.h>

#define DEBUG_LOG(fmt, ...) \
do {								\
	printf("%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
}while (0)

inline uint64_t htonll(uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint64_t y = ((0x00000000000000ff & x) << 56) |
		     ((0x000000000000ff00 & x) << 40) |
		     ((0x0000000000ff0000 & x) << 24) |
		     ((0x00000000ff000000 & x) << 8 ) |
		     ((0x000000ff00000000 & x) >> 8 ) |
		     ((0x0000ff0000000000 & x) >> 24) |
		     ((0x00ff000000000000 & x) >> 40) |
		     ((0xff00000000000000 & x) >> 56);
	return y;
#else
	return x;
#endif
}

inline uint64_t ntohll(uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint64_t y = ((0xff00000000000000 & x) >> 56) |
		     ((0x00ff000000000000 & x) >> 40) |
		     ((0x0000ff0000000000 & x) >> 24) |
		     ((0x000000ff00000000 & x) >> 8 ) |
		     ((0x00000000ff000000 & x) << 8 ) |
		     ((0x0000000000ff0000 & x) << 24) |
		     ((0x000000000000ff00 & x) << 40) |
		     ((0x00000000000000ff & x) << 56);
	return y;
#else
	return x;
#endif
}

// Open a socket to another process/machine
int createSocket(std::string addr, std::string port);
// Create a thread with specified affinity
bool create_thread(pthread_t &thread, void *(*start_routine)(void *),
		   void *arg, std::string cpu_mask);
// Populate a cpu-mask from a string and other assorted cpu_set_t ops
void cpumask_from_str(cpu_set_t &mask, std::string str);
int cpumask_first(cpu_set_t mask);
int cpumask_first(cpu_set_t mask);
int cpumask_next(cpu_set_t mask, int cpu);

// Hash string to get a uuid
uint64_t hashString(std::string str);
#endif
