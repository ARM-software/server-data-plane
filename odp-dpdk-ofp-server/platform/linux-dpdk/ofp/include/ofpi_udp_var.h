/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)udp_var.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: release/9.1.0/sys/netinet/udp_var.h 234780 2012-04-29 08:50:50Z bz $
 */

#ifndef _NETINET_UDP_VAR_H_
#define	_NETINET_UDP_VAR_H_

#include "ofpi_sockopt.h"
#include "ofpi_ip_var.h"
#include "ofpi_udp.h"
#include "api/ofp_sysctl.h"

struct mbuf;
//struct inpcb;

/*
 * UDP kernel structures and variables.
 */
struct udpiphdr {
	struct ipovly	ui_i;		/* overlaid ip structure */
	struct ofp_udphdr	ui_u;		/* udp header */
};
#define	ui_x1		ui_i.ih_x1
#define	ui_pr		ui_i.ih_pr
#define	ui_len		ui_i.ih_len
#define	ui_src		ui_i.ih_src
#define	ui_dst		ui_i.ih_dst
#define	ui_sport	ui_u.uh_sport
#define	ui_dport	ui_u.uh_dport
#define	ui_ulen		ui_u.uh_ulen
#define	ui_sum		ui_u.uh_sum

typedef void(*udp_tun_func_t)(odp_packet_t , int off, struct inpcb *);

/*
 * UDP control block; one per udp.
 */
struct udpcb {
	udp_tun_func_t	u_tun_func;	/* UDP kernel tunneling callback. */
	uint32_t		u_flags;	/* Generic UDP flags. */
};

#define	intoudpcb(ip)	((struct udpcb *)(ip)->inp_ppcb)
#define	sotoudpcb(so)	(intoudpcb(sotoinpcb(so)))

struct ofp_udpstat {
				/* input statistics: */
	uint64_t	udps_ipackets;		/* total input packets */
	uint64_t	udps_hdrops;		/* packet shorter than header */
	uint64_t	udps_badsum;		/* checksum error */
	uint64_t	udps_nosum;		/* no checksum */
	uint64_t	udps_badlen;		/* data length larger than packet */
	uint64_t	udps_noport;		/* no socket on port */
	uint64_t	udps_noportbcast;	/* of above, arrived as broadcast */
	uint64_t	udps_fullsock;		/* not delivered, input socket full */
	uint64_t	udpps_pcbcachemiss;	/* input packets missing pcb cache */
	uint64_t	udpps_pcbhashmiss;	/* input packets not for hashed pcb */
				/* output statistics: */
	uint64_t	udps_opackets;		/* total output packets */
	uint64_t	udps_fastout;		/* output packets on fast path */
	/* of no socket on port, arrived as multicast */
	uint64_t	udps_noportmcast;
	uint64_t	udps_filtermcast;	/* blocked by multicast filter */
};

/*
 * Names for UDP sysctl objects.
 */
#define	UDPCTL_CHECKSUM		1	/* checksum UDP packets */
#define	UDPCTL_STATS		2	/* statistics (read-only) */
#define	UDPCTL_MAXDGRAM		3	/* max datagram size */
#define	UDPCTL_RECVSPACE	4	/* default receive buffer space */
#define	UDPCTL_PCBLIST		5	/* list of PCBs for UDP sockets */
#define	UDPCTL_MAXID		6

#define	UDPCTL_NAMES	{						\
	{ 0, 0 },							\
	{ "checksum", OFP_CTLTYPE_INT },					\
	{ "stats", OFP_CTLTYPE_STRUCT },					\
	{ "maxdgram", OFP_CTLTYPE_INT },					\
	{ "recvspace", OFP_CTLTYPE_INT },					\
	{ "pcblist", OFP_CTLTYPE_STRUCT },					\
}

SYSCTL_DECL(_net_inet_udp);

extern struct inpcbinfo ofp_udbinfo;
extern struct pr_usrreqs	ofp_udp_usrreqs;
extern uint64_t			ofp_udp_sendspace;
extern uint64_t			ofp_udp_recvspace;

int		 udp_newudpcb(struct inpcb *);
void		 udp_discardcb(struct udpcb *);

struct ofp_sockaddr;
void		 ofp_udp_ctlinput(int, struct ofp_sockaddr *, void *);
int		 ofp_udp_ctloutput(struct socket *, struct sockopt *);
void		 ofp_udp_init(void);
void		 ofp_udp_destroy(void);
enum ofp_return_code ofp_udp_input(odp_packet_t , int);
struct inpcb	*ofp_udp_notify(struct inpcb *, int);
int		 ofp_udp_shutdown(struct socket *so);

#endif
