/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef __OFPI_INIT_H__
#define __OFPI_INIT_H__

#include <odp.h>

#include "ofpi_hook.h"

#define SHM_NAME_GLOBAL_CONFIG "OfpGlobalConfigShMem"

extern odp_pool_t ofp_packet_pool;
extern odp_cpumask_t cpumask;

int ofp_init_pre_global(const char *pool_name,
			odp_pool_param_t *pool_params,
			ofp_pkt_hook hooks[], odp_pool_t *pool,
			int arp_age_interval, int arp_entry_timeout);

int ofp_term_post_global(const char *pool_name);

struct ofp_global_config_mem {
	odp_bool_t is_running ODP_ALIGNED_CACHE;

#ifdef SP
	linux_pthread_t nl_thread;
	odp_bool_t nl_thread_is_running;
#endif /* SP */

	linux_pthread_t cli_thread;
	odp_bool_t cli_thread_is_running;
};

struct ofp_global_config_mem *ofp_get_global_config(void);

#endif /* __OFPI_INIT_H__ */
