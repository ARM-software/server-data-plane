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

#include <cstdio>
#include <cstdlib>

#include "include/protocol.hh"
#include "include/util.hh"

static const char *data_str = "All work and no play makes Geoff a dull boy. "
			      "All work and no play makes Geoff a dull boy. "
			      "All work and no play makes Geoff a dull boy. "
			      "All work and no play makes Geoff a dull boy. "
			      "All work and no play makes Geoff a dull boy. ";

// Will open 1 connection and do some writes to load the app and 
// then do a mix of reads and writes.
int main(int argc, char **argv)
{
	// Usage: <app> <server> <port> <num ops>
	if (argc < 4) {
		printf("Usage: %s <server> <port> <num ops>\n", argv[0]);
		return -1;
	}

	// Create a socket to connect to the server
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, ret;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	ret = getaddrinfo(argv[1], argv[2], &hints, &result);
	if (ret != 0) {
		DEBUG_LOG("getaddrinfo: %s\n", gai_strerror(ret));
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
	}
	printf("Connected to server\n");
	// Should be connected here.

	// Create some random writes to the server to load it
	char buffer[256*4096];
	char rbuffer[256*4096];
	for (int i = 0; i < 1024; i++) {
		// Setup our header
		struct msg_header *hdr = (struct msg_header*)buffer;
		hdr->magic = MAGIC_NUM;
		hdr->msg_type = QDOFS_CREATE;
		hdr->file_offset = 0;
		hdr->file_read_len = 0;
		hdr->data_len = htonl(random() % 16384);
		if (ntohl(hdr->data_len) < 64) hdr->data_len = htonl(64);
		hdr->xaction_uuid = htonll(i);

		// Fill in the file id
		hdr->fileid_len = htonl(sprintf(buffer + sizeof(struct msg_header), "file%d.dat", i));

		// fill in the data
		int static_data_sz = strlen(data_str);
		char *buf = buffer +  sizeof(struct msg_header) + ntohl(hdr->fileid_len);
		int size_to_fill = ntohl(hdr->data_len);
		for (int j = 0; j < ntohl(hdr->data_len) / static_data_sz; j++) {
			memcpy(buf, data_str, static_data_sz);
			buf += static_data_sz;
			size_to_fill -= static_data_sz;
		}
		// Fill any left over space;
		memcpy(buf, data_str, size_to_fill);
		hdr->total_payload = htonl(ntohl(hdr->fileid_len) +
					   ntohl(hdr->data_len) +
					   sizeof(struct msg_footer));

		// populate the footer
		// TODO: Empty for now, and not likely to be done

		// Send
		int packet_size = sizeof(struct msg_header) + ntohl(hdr->total_payload);
		int ret = send(sfd, buffer, packet_size, 0);
		if (ret < packet_size) {
			DEBUG_LOG("Failed to send a full message to the kernel?\n");
			close(sfd);
			return -1;
		}

		// Wait for response and check it is valid
		packet_size = sizeof(struct msg_header) + sizeof(struct msg_footer);
		int recvd = 0;
		while (recvd < packet_size) {
			ret = recv(sfd, rbuffer + recvd, packet_size - recvd, 0);
			recvd += packet_size;
		}

		struct msg_header *rhdr = (struct msg_header*)rbuffer;
		assert(rhdr->magic == MAGIC_NUM_RESP);
		assert(rhdr->msg_type == QDOFS_CREATE);
		assert(rhdr->xaction_uuid == hdr->xaction_uuid);
	}

	// Do a mix of reads and writes to the server to see if it works
	for (int i = 0; i < 2048; i++) {
		int type = random() % 2;
		int file = random() % 1024;

		// Setup our header
		struct msg_header *hdr = (struct msg_header*)buffer;
		hdr->magic = MAGIC_NUM;
		hdr->msg_type = type ? QDOFS_READ : QDOFS_WRITE;
		hdr->file_offset = 0;
		hdr->file_read_len = type ? htonll(random() % 16384) : 0;
		hdr->data_len = type ? 0 : htonl(random() % 16384);
		if (ntohl(hdr->data_len) < 64) hdr->data_len = htonl(64);
		hdr->xaction_uuid = htonll(i);

		// Fill in the file id
		hdr->fileid_len = htonl(sprintf(buffer + sizeof(struct msg_header), "file%d.dat", file));

		// fill in the data
		if (type == 0) {
			int static_data_sz = strlen(data_str);
			char *buf = buffer +  sizeof(struct msg_header) + ntohl(hdr->fileid_len);
			int size_to_fill = ntohl(hdr->data_len);
			for (int j = 0; j < ntohl(hdr->data_len) / static_data_sz; j++) {
				memcpy(buf, data_str, static_data_sz);
				buf += static_data_sz;
				size_to_fill -= static_data_sz;
			}
			// Fill any left over space;
			memcpy(buf, data_str, size_to_fill);
		}
		hdr->total_payload = htonl(ntohl(hdr->fileid_len) +
					   ntohl(hdr->data_len) +
					   sizeof(struct msg_footer));

		// populate the footer
		// TODO: Empty for now, but do it later

		// Send
		int packet_size = sizeof(struct msg_header) + ntohl(hdr->total_payload);
		int ret = send(sfd, buffer, packet_size, 0);
		if (ret < packet_size) {
			DEBUG_LOG("Failed to send a full message to the kernel?\n");
			close(sfd);
			return -1;
		}

		// read in the header first to get reply size
		int hdr_size = sizeof(struct msg_header);
		int recvd = 0;
		while (recvd < hdr_size) {
			ret = recv(sfd, rbuffer + recvd, hdr_size - recvd, 0);
			recvd += ret;
		}
		struct msg_header *rhdr = (struct msg_header*)rbuffer;

		// Wait for response and check it is valid
		packet_size = ntohl(rhdr->total_payload) + sizeof(struct msg_header);

		while (recvd < packet_size) {
			ret = recv(sfd, rbuffer + recvd, packet_size - recvd, 0);
			recvd += ret;
		}

		assert(rhdr->magic == MAGIC_NUM_RESP);
		assert(rhdr->msg_type == hdr->msg_type);
		assert(rhdr->xaction_uuid == hdr->xaction_uuid);
	}

	close(sfd);
	return 0;
}
