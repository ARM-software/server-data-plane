/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Intenal Linux helper
 *
 * This file is a helper include file for OFP to bootstrap
 * itself into the ODP environment as an internal service instead
 * of a controlling entity.
 */

#ifndef ODP_LINUX_HELPER_H_
#define ODP_LINUX_HELPER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

#include <pthread.h>
#include <getopt.h>
#include <sys/types.h>

/** @addtogroup odph_linux ODPH LINUX
 *  @{
 */

/** Thread parameter for Linux pthreads and processes */
typedef struct {
	void *(*start)(void *);    /**< Thread entry point function */
	void *arg;                  /**< Argument for the function */
	odp_thread_type_t thr_type; /**< ODP thread type */
	odp_instance_t instance;    /**< ODP instance handle */
} linux_thr_params_t;

/** Linux pthread state information */
typedef struct {
	pthread_t      thread; /**< Pthread ID */
	pthread_attr_t attr;   /**< Pthread attributes */
	int            cpu;    /**< CPU ID */
	/** Copy of thread params */
	linux_thr_params_t thr_params;
} linux_pthread_t;

/** Linux process state information */
typedef struct {
	pid_t pid;      /**< Process ID */
	int   cpu;      /**< CPU ID */
	int   status;   /**< Process state change status */
} linux_process_t;

/** odpthread linux type: whether an ODP thread is a linux thread or process */
typedef enum odpthread_linuxtype_e {
	ODPTHREAD_NOT_STARTED = 0,
	ODPTHREAD_PROCESS,
	ODPTHREAD_PTHREAD
} odpthread_linuxtype_t;

/** odpthread parameters for odp threads (pthreads and processes) */
typedef struct {
	int (*start)(void *);       /**< Thread entry point function */
	void *arg;                  /**< Argument for the function */
	odp_thread_type_t thr_type; /**< ODP thread type */
	odp_instance_t instance;    /**< ODP instance handle */
} odpthread_params_t;

/** The odpthread starting arguments, used both in process or thread mode */
typedef struct {
	odpthread_linuxtype_t linuxtype; /**< process or pthread */
	odpthread_params_t thr_params; /**< odpthread start parameters */
} odpthread_start_args_t;

/** Linux odpthread state information, used both in process or thread mode */
typedef struct {
	odpthread_start_args_t	start_args; /**< start arguments */
	int				cpu;	/**< CPU ID */
	int				last;   /**< true if last table entry */
	union {
		struct { /* for thread implementation */
			pthread_t	thread_id; /**< Pthread ID */
			pthread_attr_t	attr;	/**< Pthread attributes */
		} thread;
		struct { /* for process implementation */
			pid_t		pid;	/**< Process ID */
			int		status;	/**< Process state chge status*/
		} proc;
	};
} odpthread_t;

/**
 * Creates and launches pthreads
 *
 * Creates, pins and launches threads to separate CPU's based on the cpumask.
 *
 * @param[out] pthread_tbl Table of pthread state information records. Table
 *                         must have at least as many entries as there are
 *                         CPUs in the CPU mask.
 * @param      mask        CPU mask
 * @param      thr_params  Linux helper thread parameters
 *
 * @return Number of threads created
 */
int linux_pthread_create(linux_pthread_t *pthread_tbl,
			 const odp_cpumask_t *mask,
			 const linux_thr_params_t *thr_params);

/**
 * Waits pthreads to exit
 *
 * Returns when all threads have been exit.
 *
 * @param thread_tbl    Thread table
 * @param num           Number of threads to create
 *
 */
void linux_pthread_join(linux_pthread_t *thread_tbl, int num);

/**
 * Fork a process
 *
 * Forks and sets CPU affinity for the child process. Ignores 'start' and 'arg'
 * thread parameters.
 *
 * @param[out] proc        Pointer to process state info (for output)
 * @param      cpu         Destination CPU for the child process
 * @param      thr_params  Linux helper thread parameters
 *
 * @return On success: 1 for the parent, 0 for the child
 *         On failure: -1 for the parent, -2 for the child
 */
int linux_process_fork(linux_process_t *proc, int cpu,
		       const linux_thr_params_t *thr_params);


/**
 * Fork a number of processes
 *
 * Forks and sets CPU affinity for child processes. Ignores 'start' and 'arg'
 * thread parameters.
 *
 * @param[out] proc_tbl    Process state info table (for output)
 * @param      mask        CPU mask of processes to create
 * @param      thr_params  Linux helper thread parameters
 *
 * @return On success: 1 for the parent, 0 for the child
 *         On failure: -1 for the parent, -2 for the child
 */
int linux_process_fork_n(linux_process_t *proc_tbl,
			      const odp_cpumask_t *mask,
			      const linux_thr_params_t *thr_params);


/**
 * Wait for a number of processes
 *
 * Waits for a number of child processes to terminate. Records process state
 * change status into the process state info structure.
 *
 * @param proc_tbl      Process state info table (previously filled by fork)
 * @param num           Number of processes to wait
 *
 * @return 0 on success, -1 on failure
 */
int linux_process_wait_n(linux_process_t *proc_tbl, int num);

/**
 * Creates and launches odpthreads (as linux threads or processes)
 *
 * Creates, pins and launches threads to separate CPU's based on the cpumask.
 *
 * @param thread_tbl    Thread table
 * @param mask          CPU mask
 * @param thr_params    ODP thread parameters
 *
 * @return Number of threads created
 */
int odpthreads_create(odpthread_t *thread_tbl,
		      const odp_cpumask_t *mask,
		      const odpthread_params_t *thr_params);

/**
 * Waits odpthreads (as linux threads or processes) to exit.
 *
 * Returns when all odpthreads have terminated.
 *
 * @param thread_tbl    Thread table
 * @return The number of joined threads or -1 on error.
 * (error occurs if any of the start_routine return non-zero or if
 *  the thread join/process wait itself failed -e.g. as the result of a kill)
 *
 */
int odpthreads_join(odpthread_t *thread_tbl);

/**
 * Set CPU affinity of the current odp thread
 *
 * CPU affinity determines the CPU core on which the thread is
 * eligible to run.
 *
 * @param cpu           The affinity CPU core
 *
 * @return 0 on success, -1 on failure
 */
int odpthread_setaffinity(const int cpu);

/**
 * Get CPU affinity of the current odp thread
 *
 * CPU affinity determines the CPU core on which the thread is
 * eligible to run.
 *
 * @return positive cpu ID on success, -1 on failure
 */
int odpthread_getaffinity(void);

/**
 * Merge getopt options
 *
 * Given two sets of getopt options (each containing possibly both short
 * options -a string- and long options -a option array-) this function
 * return a single set (i.e. a string for short and an array for long)
 * being the concatenation of the two given sets.
 * Due to the fact that the size of these arrays is unknown at compilation
 * time, this function actually mallocs the the resulting arrays.
 * The fourth and fith parameters are actually pointers where these malloc'ed
 * areas are returned.
 * This means that the caller of this function has to free the two returned
 * areas!
 *
 * @param shortopts1 first set of short options (a string)
 * @param shortopts2 second set of short options (a string)
 * @param longopts1  first set of long options (a getopt option array)
 * @param longopts2  second set of long options (a getopt option array)
 * @param shortopts  a pointer where the address of the short options list
 *		     (a string) is returned. It contains the concatenation of
 *		     the two given short option strings.
 * @param longopts   a pointer where the address of the long options list
 *		     (a getopt option array) is returned.
 *		     It contains the concatenation of the two given long
 *		     option arrays.
 * if any of shortopts1, shortopts2, longopts1, longopts2 is NULL, the
 * corresponding list as assumed to be empty.
 * if any of shortopts, longopts is NULL, the corresponding malloc is not
 * performed.
 *
 * @return On success: 0 : both shortopts and longopts are returned (assuming
 *			   the given pointer where not null), possibly
 *			   pointing to an empty string or an empty option array.
 *			   On success, the caller is due to free these areas.
 *	   On failure: -1: Nothing is malloc'ed.
 */
int merge_getopt_options(const char *shortopts1,
			 const char *shortopts2,
			 const struct option *longopts1,
			 const struct option *longopts2,
			 char **shortopts,
			 struct option **longopts);

/**
 * Parse linux helper options
 *
 * Parse the command line options. Pick up options meant for the helper itself.
 * If the caller is also having a set of option to parse, it should include
 * their description here (shortopts desribes the short options and longopts
 * describes the long options, as for getopt_long()).
 * This function will issue errors on unknown arguments, so callers failing
 * to pass their own command line options description here will see their
 * options rejected.
 * (the caller wants to set opterr to zero when parsing its own stuff
 * with getopts to avoid reacting on helper's options).
 *
 * @param argc argument count
 * @param argv argument values
 * @param caller_shortopts caller's set of short options (string). or NULL.
 * @param caller_longopts  caller's set of long options (getopt option array).
 *			   or NULL.
 *
 * @return On success: 0
 *	   On failure: -1 failure occurs if a value passed for a helper
 *			  option is invalid, or on meeting unknown options.
 */
int parse_options(int argc, char *argv[],
		  const char *caller_shortopts,
		  const struct option *caller_longopts);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
