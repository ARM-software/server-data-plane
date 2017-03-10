/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 * Author: Geoffrey Blake (R&D SLSS)
 */


/**
 * @file
 *
 * ODP Stream Packetizer
 */

#ifndef ODP_STREAM_PACKETIZER_TYPES_H_
#define ODP_STREAM_PACKETIZER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

typedef ODP_HANDLE_T(odp_packetizer_t);

#define ODP_PACKETIZER_INVALID _odp_cast_scalar(odp_packetizer_t, 0xffffffff)

#ifdef __cplusplus
}
#endif
#endif
