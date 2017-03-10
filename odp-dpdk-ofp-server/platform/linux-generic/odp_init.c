/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp/api/init.h>
#include <odp_debug_internal.h>
#include <odp/api/epoll.h>
#include <odp/api/debug.h>
#include <unistd.h>
#include <odp_internal.h>
#include <odp_schedule_if.h>
#include <string.h>

struct odp_global_data_s odp_global_data;

int odp_init_global(odp_instance_t *instance,
		    const odp_init_t *params,
		    const odp_platform_init_t *platform_params)
{
	memset(&odp_global_data, 0, sizeof(struct odp_global_data_s));
	odp_global_data.main_pid = getpid();
	if (platform_params)
		odp_global_data.ipc_ns = platform_params->ipc_ns;

	enum init_stage stage = NO_INIT;
	odp_global_data.log_fn = odp_override_log;
	odp_global_data.abort_fn = odp_override_abort;

	if (params != NULL) {
		if (params->log_fn != NULL)
			odp_global_data.log_fn = params->log_fn;
		if (params->abort_fn != NULL)
			odp_global_data.abort_fn = params->abort_fn;
	}

	if (odp_cpumask_init_global(params)) {
		ODP_ERR("ODP cpumask init failed.\n");
		goto init_failed;
	}
	stage = CPUMASK_INIT;

	if (odp_time_init_global()) {
		ODP_ERR("ODP time init failed.\n");
		goto init_failed;
	}
	stage = TIME_INIT;

	if (odp_system_info_init()) {
		ODP_ERR("ODP system_info init failed.\n");
		goto init_failed;
	}
	stage = SYSINFO_INIT;

	if (odp_shm_init_global()) {
		ODP_ERR("ODP shm init failed.\n");
		goto init_failed;
	}
	stage = SHM_INIT;

	if (odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
		goto init_failed;
	}
	stage = THREAD_INIT;

	if (odp_pool_init_global()) {
		ODP_ERR("ODP pool init failed.\n");
		goto init_failed;
	}
	stage = POOL_INIT;

	if (odp_queue_init_global()) {
		ODP_ERR("ODP queue init failed.\n");
		goto init_failed;
	}
	stage = QUEUE_INIT;

	if (sched_fn->init_global()) {
		ODP_ERR("ODP schedule init failed.\n");
		goto init_failed;
	}
	stage = SCHED_INIT;

	if (odp_pktio_init_global()) {
		ODP_ERR("ODP packet io init failed.\n");
		goto init_failed;
	}
	stage = PKTIO_INIT;

	if (odp_timer_init_global()) {
		ODP_ERR("ODP timer init failed.\n");
		goto init_failed;
	}
	stage = TIMER_INIT;

	if (odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		goto init_failed;
	}
	stage = CRYPTO_INIT;

	if (odp_classification_init_global()) {
		ODP_ERR("ODP classification init failed.\n");
		goto init_failed;
	}
	stage = CLASSIFICATION_INIT;

	if (odp_tm_init_global()) {
		ODP_ERR("ODP traffic manager init failed\n");
		goto init_failed;
	}
	stage = TRAFFIC_MNGR_INIT;

	if (_odp_int_name_tbl_init_global()) {
		ODP_ERR("ODP name table init failed\n");
		goto init_failed;
	}
	stage = NAME_TABLE_INIT;

	if (odp_sockio_init_global()) {
		ODP_ERR("ODP socket io init failed.\n");
		return -1;
	}
	stage = SOCKIO_INIT;

	if (odp_packetizer_init_global()) {
		ODP_ERR("ODP packetizer init failed.\n");
		goto init_failed;
	}
	stage = PKTIZER_INIT;

	if (odp_epoll_init_global()) {
		ODP_ERR("ODP epoll init failed.\n");
		goto init_failed;
	}
	stage = EPOLL_INIT;
	stage = ALL_INIT;

	/* Dummy support for single instance */
	*instance = INSTANCE_ID;

	return 0;

init_failed:
	_odp_term_global(stage);
	return -1;
}

int odp_term_global(odp_instance_t instance)
{
	if (instance != INSTANCE_ID) {
		ODP_ERR("Bad instance.\n");
		return -1;
	}
	return _odp_term_global(ALL_INIT);
}

int _odp_term_global(enum init_stage stage)
{
	int rc = 0;

	switch (stage) {
	case ALL_INIT:
	case EPOLL_INIT:
		if (odp_epoll_term_global()) {
			ODP_ERR("Epoll term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case PKTIZER_INIT:
		if (odp_packetizer_term_global()) {
			ODP_ERR("Packetizer term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SOCKIO_INIT:
		if (odp_sockio_term_global()) {
			ODP_ERR("Sockio term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case NAME_TABLE_INIT:
		if (_odp_int_name_tbl_term_global()) {
			ODP_ERR("Name table term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TRAFFIC_MNGR_INIT:
		if (odp_tm_term_global()) {
			ODP_ERR("TM term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CLASSIFICATION_INIT:
		if (odp_classification_term_global()) {
			ODP_ERR("ODP classification term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CRYPTO_INIT:
		if (odp_crypto_term_global()) {
			ODP_ERR("ODP crypto term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIMER_INIT:
		if (odp_timer_term_global()) {
			ODP_ERR("ODP timer term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case PKTIO_INIT:
		if (odp_pktio_term_global()) {
			ODP_ERR("ODP pktio term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SCHED_INIT:
		if (sched_fn->term_global()) {
			ODP_ERR("ODP schedule term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case QUEUE_INIT:
		if (odp_queue_term_global()) {
			ODP_ERR("ODP queue term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (odp_pool_term_global()) {
			ODP_ERR("ODP buffer pool term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		if (odp_thread_term_global()) {
			ODP_ERR("ODP thread term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SHM_INIT:
		if (odp_shm_term_global()) {
			ODP_ERR("ODP shm term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SYSINFO_INIT:
		if (odp_system_info_term()) {
			ODP_ERR("ODP system info term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIME_INIT:
		if (odp_time_term_global()) {
			ODP_ERR("ODP time term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CPUMASK_INIT:
		if (odp_cpumask_term_global()) {
			ODP_ERR("ODP cpumask term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case NO_INIT:
		;
	}

	return rc;
}

int odp_init_local(odp_instance_t instance, odp_thread_type_t thr_type)
{
	enum init_stage stage = NO_INIT;

	if (instance != INSTANCE_ID) {
		ODP_ERR("Bad instance.\n");
		goto init_fail;
	}

	if (odp_shm_init_local()) {
		ODP_ERR("ODP shm local init failed.\n");
		goto init_fail;
	}
	stage = SHM_INIT;

	if (odp_thread_init_local(thr_type)) {
		ODP_ERR("ODP thread local init failed.\n");
		goto init_fail;
	}
	stage = THREAD_INIT;

	if (odp_pktio_init_local()) {
		ODP_ERR("ODP packet io local init failed.\n");
		goto init_fail;
	}
	stage = PKTIO_INIT;

	if (odp_pool_init_local()) {
		ODP_ERR("ODP pool local init failed.\n");
		goto init_fail;
	}
	stage = POOL_INIT;

	if (sched_fn->init_local()) {
		ODP_ERR("ODP schedule local init failed.\n");
		goto init_fail;
	}
	/* stage = SCHED_INIT; */

	return 0;

init_fail:
	_odp_term_local(stage);
	return -1;
}

int odp_term_local(void)
{
	return _odp_term_local(ALL_INIT);
}

int _odp_term_local(enum init_stage stage)
{
	int rc = 0;
	int rc_thd = 0;

	switch (stage) {
	case ALL_INIT:

	case SCHED_INIT:
		if (sched_fn->term_local()) {
			ODP_ERR("ODP schedule local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (odp_pool_term_local()) {
			ODP_ERR("ODP buffer pool local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		rc_thd = odp_thread_term_local();
		if (rc_thd < 0) {
			ODP_ERR("ODP thread local term failed.\n");
			rc = -1;
		} else {
			if (!rc)
				rc = rc_thd;
		}
		/* Fall through */

	default:
		break;
	}

	return rc;
}
