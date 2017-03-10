/* Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/event.h>
#include <odp/api/buffer.h>
#include <odp/api/crypto.h>
#include <odp/api/packet.h>
#include <odp/api/timer.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_debug_internal.h>
#include <odp_fileio_internal.h>
#include <odp_socket_io_internal.h>

odp_event_type_t odp_event_type(odp_event_t event)
{
	return _odp_buffer_event_type(odp_buffer_from_event(event));
}

void odp_event_free(odp_event_t event)
{
	switch (odp_event_type(event)) {
	case ODP_EVENT_BUFFER:
		odp_buffer_free(odp_buffer_from_event(event));
		break;
	case ODP_EVENT_PACKET:
		odp_packet_free(odp_packet_from_event(event));
		break;
	case ODP_EVENT_TIMEOUT:
		odp_timeout_free(odp_timeout_from_event(event));
		break;
	case ODP_EVENT_CRYPTO_COMPL:
		odp_crypto_compl_free(odp_crypto_compl_from_event(event));
		break;
	case ODP_EVENT_SOCKET_CONNECT:
		// Contains a connect_ev structure that uses a simple buffer
		odp_sockio_accept_free(odp_buffer_from_event(event));
		break;
	case ODP_EVENT_FILE_IO_COMPL:
		// Contains a simple fileio_cmd_t structure that utilizes a
		// buffer
		odp_fileio_cmpl_free(odp_buffer_from_event(event));
		break;
	default:
		ODP_ABORT("Invalid event type: %d\n", odp_event_type(event));
	}
}
