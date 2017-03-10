/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_HASH_H_
#define _ODP_TEST_HASH_H_

#include <odp_cunit_common.h>

/* test functions: */
void hash_test_crc32c(void);

/* test arrays: */
extern odp_testinfo_t hash_suite[];

/* test registry: */
extern odp_suiteinfo_t hash_suites[];

/* main test program: */
int hash_main(int argc, char *argv[]);

#endif
