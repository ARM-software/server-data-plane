/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_CPU_ARCH_H_
#define ODP_PLAT_CPU_ARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#define _ODP_CACHE_LINE_SIZE 64

static inline void odp_cpu_pause(void)
{
}

#ifdef __cplusplus
}
#endif

#endif
