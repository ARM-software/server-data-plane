/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PLAT_PACKET_H_
#define ODP_PLAT_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/event_types.h>
#include <odp/api/plat/packet_io_types.h>
#include <odp/api/plat/packet_types.h>
#include <odp/api/plat/buffer_types.h>
#include <odp/api/plat/pool_types.h>

/** @ingroup odp_packet
 *  @{
 */

#include <odp/api/inlines.h>
#ifdef _ODP_INLINES
#include <odp/api/packet_inlines.h>
#endif

/**
 * @}
 */

#include <odp/api/spec/packet.h>

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_H_ */
