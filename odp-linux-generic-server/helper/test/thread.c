/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <test_debug.h>
#include <odp_api.h>
#include <odp/helper/linux.h>

#define NUMBER_WORKERS 16
static void *worker_fn(void *arg TEST_UNUSED)
{
	/* depend on the odp helper to call odp_init_local */

	printf("Worker thread on CPU %d\n", odp_cpu_id());

	/* depend on the odp helper to call odp_term_local */

	return NULL;
}

/* Create additional dataplane threads */
int main(int argc TEST_UNUSED, char *argv[] TEST_UNUSED)
{
	odph_linux_pthread_t thread_tbl[NUMBER_WORKERS];
	odp_cpumask_t cpu_mask;
	int num_workers;
	int cpu;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_instance_t instance;
	odph_linux_thr_params_t thr_params;

	if (odp_init_global(&instance, NULL, NULL)) {
		LOG_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		LOG_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* discover how many threads this system can support */
	num_workers = odp_cpumask_default_worker(&cpu_mask, NUMBER_WORKERS);
	if (num_workers < NUMBER_WORKERS) {
		printf("System can only support %d threads and not the %d requested\n",
		       num_workers, NUMBER_WORKERS);
	}

	/* generate a summary for the user */
	(void)odp_cpumask_to_str(&cpu_mask, cpumaskstr, sizeof(cpumaskstr));
	printf("default cpu mask:           %s\n", cpumaskstr);
	printf("default num worker threads: %i\n", num_workers);

	cpu = odp_cpumask_first(&cpu_mask);
	printf("the first CPU:              %i\n", cpu);

	/* reserve cpu 0 for the control plane so remove it from
	 * the default mask */
	odp_cpumask_clr(&cpu_mask, 0);
	num_workers = odp_cpumask_count(&cpu_mask);
	(void)odp_cpumask_to_str(&cpu_mask, cpumaskstr, sizeof(cpumaskstr));
	printf("new cpu mask:               %s\n", cpumaskstr);
	printf("new num worker threads:     %i\n\n", num_workers);

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = worker_fn;
	thr_params.arg      = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	odph_linux_pthread_create(&thread_tbl[0], &cpu_mask, &thr_params);
	odph_linux_pthread_join(thread_tbl, num_workers);

	if (odp_term_local()) {
		LOG_ERR("Error: ODP local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		LOG_ERR("Error: ODP global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
