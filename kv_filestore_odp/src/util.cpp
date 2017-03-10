/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <arpa/inet.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#include <cstdlib>
#include <string>

#include "include/util.hh"

int createSocket(std::string addr, std::string port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	ret = getaddrinfo(addr.c_str(), port.c_str(), &hints, &result);
	if (ret != 0) {
		printf("getaddrinfo: %s for address %s:%s\n", gai_strerror(ret),
		       addr.c_str(), port.c_str());
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) {
			continue;
		}
		ret = connect(sfd, rp->ai_addr, rp->ai_addrlen);
		if (ret == 0) {
			break;
		}
		close(sfd);
		sfd = -1;
	}
	return sfd;
}
