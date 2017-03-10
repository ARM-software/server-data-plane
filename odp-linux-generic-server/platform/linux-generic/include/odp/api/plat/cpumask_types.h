/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP CPU masks and enumeration
 */

#ifndef ODP_CPUMASK_TYPES_H_
#define ODP_CPUMASK_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_cpumask
 *  @{
 */

#include <odp/api/std_types.h>
#include <odp/api/align.h>

#define ODP_CPUMASK_SIZE 1024

#define ODP_CPUMASK_STR_SIZE ((ODP_CPUMASK_SIZE + 3) / 4 + 3)

/**
 * CPU mask
 *
 * Don't access directly, use access functions.
 */
typedef struct odp_cpumask_t {
	/** @private CPU mask storage
	  *
	  * This is private to the implementation.
	  * Don't access directly, use access functions.
	  */
	uint8_t _u8[ODP_CPUMASK_SIZE / 8];
} odp_cpumask_t ODP_ALIGNED(8);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
