/*
 * Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdint.h>
#include <memory.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <config.h>

#ifdef HAVE_QUAGGA

#include "fpm/fpm.h"

typedef struct glob_t_
{
	int server_sock;
	int sock;
} glob_t;

glob_t glob_space;
glob_t *glob = &glob_space;

int log_level = 1;

#define log(level, format...)				\
	do {						\
		if (level <= log_level) {		\
			fprintf(stderr, format);	\
			fprintf(stderr, "\n");		\
		}					\
	} while (0);

#define NUM_OF(x) (sizeof(x) / sizeof(x[0]))

#define warn_msg(format...) log(0, format)
#define err_msg(format...) log(-1, format)
#define trace log

/*
 * get_print_buf
 */
static char * get_print_buf (size_t *buf_len)
{
	static char print_bufs[16][128];
	static int counter;

	counter++;
	if (counter >= 16) {
		counter = 0;
	}

	*buf_len = 128;
	return &print_bufs[counter][0];
}

/*
 * create_listen_sock
 */
static int create_listen_sock (int port, int *sock_p)
{
	int sock;
	struct sockaddr_in addr;
	int reuse;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		err_msg(0, "Failed to create socket: %s", strerror(errno));
		return 0;
	}

	reuse = 1;
	if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		warn_msg("Failed to set reuse addr option: %s", strerror(errno));
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err_msg("Failed to bind to port %d: %s", port, strerror(errno));
		close(sock);
		return 0;
	}

	if (listen(sock, 5)) {
		err_msg("Failed to listen on socket: %s", strerror(errno));
		close(sock);
		return 0;
	}

	*sock_p = sock;
	return 1;
}

/*
 * accept_conn
 */
static int accept_conn (int listen_sock)
{
	int sock;
	struct sockaddr_in client_addr;
	unsigned int client_len;

	while (1) {
		trace(1, "Waiting for client connection...");
		client_len = sizeof(client_addr);
		sock = accept(listen_sock, (struct sockaddr *) &client_addr,
			      &client_len);

		if (sock >= 0) {
			trace(1, "Accepted client %s", inet_ntoa(client_addr.sin_addr));
			return sock;
		}

		err_msg("Failed to accept socket: %s",  strerror(errno));
	}

}

/*
 * read_fpm_msg
 */
static fpm_msg_hdr_t * read_fpm_msg (char *buf, size_t buf_len)
{
	char *cur, *end;
	int need_len, bytes_read, have_len;
	fpm_msg_hdr_t *hdr;
	int reading_full_msg;

	end = buf + buf_len;
	cur = buf;
	hdr = (fpm_msg_hdr_t *) buf;

	while (1) {
		reading_full_msg = 0;

		have_len = cur - buf;

		if (have_len < FPM_MSG_HDR_LEN) {
			need_len = FPM_MSG_HDR_LEN - have_len;
		} else {
			need_len = fpm_msg_len(hdr) - have_len;
			assert(need_len >= 0 && need_len < (end - cur));

			if (!need_len)
				return hdr;

			reading_full_msg = 1;
		}

		trace(3, "Looking to read %d bytes", need_len);
		bytes_read = read(glob->sock, cur, need_len);

		if (bytes_read <= 0) {
			err_msg("Error reading from socket: %s", strerror(errno));
			return NULL;
		}

		trace(3, "Read %d bytes", bytes_read);
		cur += bytes_read;

		if (bytes_read < need_len) {
			continue;
		}

		assert(bytes_read == need_len);

		if (reading_full_msg)
			return hdr;

		if (!fpm_msg_ok(hdr, buf_len))
		{
			assert(0);
			err_msg("Malformed fpm message");
			return NULL;
		}
	}

}

/*
 * netlink_msg_type_to_s
 */
static const char * netlink_msg_type_to_s (uint16_t type)
{
	switch (type) {

	case RTM_NEWROUTE:
		return "New route";

	case RTM_DELROUTE:
		return "Del route";

	default:
		return "Unknown";
	}
}

/*
 * netlink_prot_to_s
 */
const char *
netlink_prot_to_s (unsigned char prot)
{
	switch (prot) {

	case RTPROT_KERNEL:
		return "Kernel";

	case RTPROT_BOOT:
		return "Boot";

	case RTPROT_STATIC:
		return "Static";

	case RTPROT_ZEBRA:
		return "Zebra";

	case RTPROT_DHCP:
		return "Dhcp";

	default:
		return "Unknown";
	}
}

#define MAX_NHS 16

typedef struct netlink_nh_t {
	struct rtattr *gateway;
	int if_index;
} netlink_nh_t;

typedef struct netlink_msg_ctx_t_ {
	struct nlmsghdr *hdr;

	/*
	 * Stuff pertaining to route messages.
	 */
	struct rtmsg *rtmsg;
	struct rtattr *rtattrs[RTA_MAX + 1];

	/*
	 * Nexthops.
	 */
	struct netlink_nh_t nhs[MAX_NHS];
	int num_nhs;

	struct rtattr *dest;
	struct rtattr *src;
	int *metric;

	const char *err_msg;
} netlink_msg_ctx_t;

/*
 * netlink_msg_ctx_init
 */
static inline void
netlink_msg_ctx_init (netlink_msg_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

/*
 * netlink_msg_ctx_set_err
 */
static inline void
netlink_msg_ctx_set_err (netlink_msg_ctx_t *ctx, const char *err_msg)
{
	if (ctx->err_msg) {
		return;
	}
	ctx->err_msg = err_msg;
}

/*
 * netlink_msg_ctx_cleanup
 */
static inline void
netlink_msg_ctx_cleanup (netlink_msg_ctx_t *ctx)
{
	return;
}

/*
 * parse_rtattrs_
 */
static int parse_rtattrs_ (struct rtattr *rta, size_t len, struct rtattr**rtas,
			   int num_rtas, const char **err_msg)
{
	memset(rtas, 0, num_rtas * sizeof(rtas[0]));

	for (; len > 0; rta = RTA_NEXT(rta, len)) {
		if (!RTA_OK(rta, len)) {
			*err_msg = "Malformed rta";
			return 0;
		}

		if (rta->rta_type >= num_rtas) {
			warn("Unknown rtattr type %d", rta->rta_type);
			continue;
		}

		rtas[rta->rta_type] = rta;
	}
}

/*
 * parse_rtattrs
 */
static int parse_rtattrs (netlink_msg_ctx_t *ctx, struct rtattr *rta, size_t len)
{
	const char *err_msg;

	err_msg = NULL;

	if (!parse_rtattrs_(rta, len, ctx->rtattrs, NUM_OF(ctx->rtattrs),
			    &err_msg)) {
		netlink_msg_ctx_set_err(ctx, err_msg);
		return 0;
	}

	return 1;
}

/*
 * netlink_msg_ctx_add_nh
 */
static int netlink_msg_ctx_add_nh (netlink_msg_ctx_t *ctx, int if_index,
				   struct rtattr *gateway)
{
	netlink_nh_t *nh;

	if (ctx->num_nhs + 1 >= NUM_OF(ctx->nhs)) {
		warn("Too many next hops");
		return 0;
	}
	nh = &ctx->nhs[ctx->num_nhs];
	ctx->num_nhs++;

	nh->gateway = gateway;
	nh->if_index = if_index;
	return 1;
}

/*
 * parse_multipath_attr
 */
static int parse_multipath_attr (netlink_msg_ctx_t *ctx, struct rtattr *mpath_rtattr)
{
	size_t len, attr_len;
	struct rtnexthop *rtnh;
	struct rtattr *rtattrs[RTA_MAX + 1];
	struct rtattr *rtattr, *gateway;
	int if_index;
	const char *err_msg;

	rtnh = RTA_DATA(mpath_rtattr);
	len = RTA_PAYLOAD(mpath_rtattr);

	for (; len > 0;
	     len -= NLMSG_ALIGN(rtnh->rtnh_len), rtnh = RTNH_NEXT(rtnh)) {

		if (!RTNH_OK(rtnh, len)) {
			netlink_msg_ctx_set_err(ctx, "Malformed nh");
			return 0;
		}

		if (rtnh->rtnh_len <= sizeof(*rtnh)) {
			netlink_msg_ctx_set_err(ctx, "NH len too small");
			return 0;
		}

		/*
		 * Parse attributes included in the nexthop.
		 */
		err_msg = NULL;
		if (!parse_rtattrs_(RTNH_DATA(rtnh), rtnh->rtnh_len - sizeof(*rtnh),
				    rtattrs, NUM_OF(rtattrs), &err_msg)) {
			netlink_msg_ctx_set_err(ctx, err_msg);
			return 0;
		}

		gateway = rtattrs[RTA_GATEWAY];
		netlink_msg_ctx_add_nh(ctx, rtnh->rtnh_ifindex, gateway);
	}

	return 1;
}

/*
 * parse_route_msg
 */
static int parse_route_msg (netlink_msg_ctx_t *ctx)
{
	int len;
	struct rtattr **rtattrs, *rtattr, *gateway, *oif;
	int if_index;

	ctx->rtmsg = NLMSG_DATA(ctx->hdr);

	len = ctx->hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));
	if (len < 0) {
		netlink_msg_ctx_set_err(ctx, "Bad message length");
		return 0;
	}

	if (!parse_rtattrs(ctx, RTM_RTA(ctx->rtmsg), len)) {
		return 0;
	}

	rtattrs = ctx->rtattrs;

	ctx->dest = rtattrs[RTA_DST];
	ctx->src = rtattrs[RTA_PREFSRC];

	rtattr = rtattrs[RTA_PRIORITY];
	if (rtattr) {
		ctx->metric = (int *) RTA_DATA(rtattr);
	}

	gateway = rtattrs[RTA_GATEWAY];
	oif = rtattrs[RTA_OIF];
	if (gateway || oif) {
		if_index = 0;
		if (oif) {
			if_index = *((int *) RTA_DATA(oif));
		}
		netlink_msg_ctx_add_nh(ctx, if_index, gateway);
	}

	rtattr = rtattrs[RTA_MULTIPATH];
	if (rtattr) {
		parse_multipath_attr(ctx, rtattr);
	}

	return 1;
}

/*
 * addr_to_s
 */
static const char * addr_to_s (unsigned char family, void *addr)
{
	size_t buf_len;
	char *buf;

	buf = get_print_buf(&buf_len);

	return inet_ntop(family, addr, buf, buf_len);
}

/*
 * netlink_msg_ctx_print
 */
static int netlink_msg_ctx_snprint (netlink_msg_ctx_t *ctx, char *buf, size_t buf_len)
{
	struct nlmsghdr *hdr;
	struct rtmsg *rtmsg;
	netlink_nh_t *nh;
	char *cur, *end;
	int i;

	hdr = ctx->hdr;
	rtmsg = ctx->rtmsg;

	cur = buf;
	end = buf + buf_len;

	cur += snprintf(cur, end - cur, "%s %s/%d, Prot: %s",
			netlink_msg_type_to_s(hdr->nlmsg_type),
			addr_to_s(rtmsg->rtm_family, RTA_DATA(ctx->dest)),
			rtmsg->rtm_dst_len,
			netlink_prot_to_s(rtmsg->rtm_protocol));

	if (ctx->metric) {
		cur += snprintf(cur, end - cur, ", Metric: %d", *ctx->metric);
	}

	for (i = 0; i < ctx->num_nhs; i++) {
		cur += snprintf(cur, end - cur, "\n ");
		nh = &ctx->nhs[i];

		if (nh->gateway) {
			cur += snprintf(cur, end - cur, " %s",
					addr_to_s(rtmsg->rtm_family, RTA_DATA(nh->gateway)));
		}

		if (nh->if_index) {
			cur += snprintf(cur, end - cur, " via interface %d", nh->if_index);
		}
	}

	return cur - buf;
}

/*
 * print_netlink_msg_ctx
 */
static void print_netlink_msg_ctx (netlink_msg_ctx_t *ctx)
{
	char buf[1024];

	netlink_msg_ctx_snprint(ctx, buf, sizeof(buf));
	log(0, "%s\n", buf);
}

/*
 * parse_netlink_msg
 */
static void parse_netlink_msg (char *buf, size_t buf_len)
{
	netlink_msg_ctx_t ctx_space, *ctx;
	struct nlmsghdr *hdr;
	int status;
	int len;

	ctx = &ctx_space;

	hdr = (struct nlmsghdr *) buf;
	len = buf_len;
	for (; NLMSG_OK (hdr, len); hdr = NLMSG_NEXT(hdr, len)) {

		netlink_msg_ctx_init(ctx);
		ctx->hdr = (struct nlmsghdr *) buf;

		switch (hdr->nlmsg_type) {

		case RTM_DELROUTE:
		case RTM_NEWROUTE:

			parse_route_msg(ctx);
			if (ctx->err_msg) {
				err_msg("Error parsing route message: %s", ctx->err_msg);
			}

			print_netlink_msg_ctx(ctx);
			break;

		default:
			trace(1, "Ignoring unknown netlink message - Type: %d", hdr->nlmsg_type);
		}

		netlink_msg_ctx_cleanup(ctx);
	}
}

/*
 * process_fpm_msg
 */
static void process_fpm_msg (fpm_msg_hdr_t *hdr)
{
	trace(1, "FPM message - Type: %d, Length %d", hdr->msg_type,
	      ntohs(hdr->msg_len));

	if (hdr->msg_type != FPM_MSG_TYPE_NETLINK) {
		warn("Unknown fpm message type %u", hdr->msg_type);
		return;
	}

	parse_netlink_msg (fpm_msg_data (hdr), fpm_msg_data_len (hdr));
}

/*
 * fpm_serve
 */
static void fpm_serve ()
{
	char buf[FPM_MAX_MSG_LEN];
	fpm_msg_hdr_t *hdr;

	while (1) {

		hdr = read_fpm_msg(buf, sizeof(buf));
		if (!hdr) {
			return;
		}

		process_fpm_msg(hdr);
	}
}

void * start_quagga_nl_server(void *arg)
{
	int sock;

	memset(glob, 0, sizeof(*glob));

	if (!create_listen_sock(FPM_DEFAULT_PORT, &glob->server_sock)) {
		err_msg("Failed to create quagga listening socket.");
		return NULL;
	}

	/*
	 * Server forever.
	 */
	while (1) {
		glob->sock = accept_conn(glob->server_sock);
		fpm_serve();
		trace(1, "Done serving client");
	}

	/* Never reached */
	return NULL;
}
#endif
