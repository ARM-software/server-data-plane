/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

#include <example_debug.h>

#include <odp.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      8192

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet bursts
 */
#define MAX_PKT_BURST          16

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define TEST_SEQ_MAGIC		0x92749451
#define TEST_SEQ_MAGIC_2	0x81638340

#define TEST_ALLOC_MAGIC	0x1234adcd

/** magic number and sequence at start of packet payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
	odp_u32be_t seq;
} pkt_head_t;

/** magic number at end of packet payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
} pkt_tail_t;

/** Application argument */
char *pktio_name;

/** Run time in seconds */
int run_time_sec;

/** IPC name space id /dev/shm/odp-nsid-objname */
int ipc_name_space;

/* helper funcs */
void parse_args(int argc, char *argv[]);
void print_info(char *progname);
void usage(char *progname);

/**
 * Create a ipc pktio handle.
 *
 * @param pool Pool to associate with device for packet RX/TX
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
odp_pktio_t create_pktio(odp_pool_t pool);

/** Spin and send all packet from table
 *
 * @param pktio		pktio device
 * @param pkt_tbl	packets table
 * @param num		number of packets
 */
int ipc_odp_packet_sendall(odp_pktio_t pktio,
			   odp_packet_t pkt_tbl[], int num);
