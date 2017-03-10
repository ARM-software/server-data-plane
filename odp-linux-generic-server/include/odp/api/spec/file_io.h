/* Copyright (c) 2017, ARM Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP File IO
 */

/* This is a first attempt at doing file/disk IO in ODP.  Currently this assumes
 * using the POSIX API for doing file IO using fd's.
 *
 * The interface is simple, allowing a user to post reads and writes for now.
 * The application is tasked with creating open file descriptors and passing
 * them to ODP.
 */

#ifndef ODP_FILE_IO_H_
#define ODP_FILE_IO_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	ODP_FILEIO_READ = 0x1,
	ODP_FILEIO_WRITE = 0x2,
} odp_fileio_op_t;

typedef struct {
	odp_fileio_op_t cmd;

	void *uid; // Allow app threads to identify this operation
	int status;
	int fd;
	int fd_offset;
	const char *file_name;
	uint64_t name_hash;
	int size;
	int buf_offset;
	odp_buffer_t buffer; // will be pre-allocated by the application

	uint64_t hash;
	odp_buffer_t iov_buf; // This will be allocated by the fileio layer and
			      // freed by it.
	int num_iovs;
} odp_fileio_cmd_t;

// Define a set of control flags for how the fileio
// will work.  Right now this is the only way to control
// behavior, for future experiments we may make this more
// complicated (more queues, different colors etc).
typedef enum {
	ODP_FILEIO_STRICT_ORDER = 0x01, // Enable 1 queue only
	// The below options cannot be used with strict ordering
	ODP_FILEIO_SEPERATE_QUEUES = 0x02, // Make some queues to parallelize work
	// Keeping it simple for now, maybe in the future can add option to bias
	// writes over reads or vice versa
} odp_fileio_config_t;

// Setup file io access parameters like basic priority for different accesses.
// Still have to make sure to keep mutual exclusion on the same fd's.
typedef struct {
	odp_fileio_config_t type; // define ordering, mutual exclusion etc.
	int num_queues;
	int cq_prio; // Set the priority of the completion queues to the
		     // application
	// Keeping it simple for now.  This could be made
	// more like the TM code with support for pipelines
	// and different queuing dynamics, but for now,
	// we are just making a few options.
} odp_fileio_params_t;

// Setup how to interact with the IO.
// Sets up symmetrical submission and completion queues.
int odp_fileio_setup(odp_fileio_params_t params);

// Post a read or write asynchronously. Here we can make guarantees
// about the system making sure reads and writes happen synchronously
// and in certain orders.
// Pass a handle so this can be used with the queues
int odp_fileio_post_async_op(odp_event_t fileio_cmd);

// Do a read or write synchronously from the view of the thread.
// These IOs happen out-of-band in regards to async reads/writes.
// We will allow mixing of these types, but the application has to 
// gaurantee the thread-safety. Modifies the passed in cmd structure.
int odp_fileio_sync_op(odp_fileio_cmd_t *cmd);

odp_fileio_cmd_t* odp_fileio_getcmd_from_event(odp_event_t ev);
int odp_fileio_event_free(odp_fileio_cmd_t* cmd);

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif
