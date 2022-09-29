
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h> /* in6_addr, IPPROTO_* */
#include <netinet/ip6.h> /* ip6_hdr */
#include <netinet/icmp6.h> /* icmp6_hdr, mld_hdr */

#include "logger.h"
#include "mld.h"
#include "mcquery.h"

#define RECV_BUF_SIZE 1024
#define SEND_BUF_SIZE 128
#define CTRL_BUF_SIZE 128

static int mld_socket;
static uint8_t *ctrl_buf;
static uint8_t *send_buf;
static uint8_t *recv_buf;

static const struct in6_addr allnodes_group = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
static const struct in6_addr allrouters_group = IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;
static const struct in6_addr allreports_group = IN6ADDR_LINKLOCAL_ALLREPORTS_INIT;

void mld_exit(void)
{
	close(mld_socket);
	free(ctrl_buf);
	free(send_buf);
	free(recv_buf);

	log_debug("MLD finished");
}

int mld_init(void)
{
	int on = 1;
	struct icmp6_filter filt;

	mld_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (mld_socket < 0)
		die("socket(ICMP6) failed");

        if (setsockopt(mld_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		die("setsockopt(SO_REUSEADDR) failed");

	/* filter all non-MLD ICMP messages */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(MLD_LISTENER_QUERY, &filt);
	ICMP6_FILTER_SETPASS(MLD_LISTENER_REPORT, &filt);
	ICMP6_FILTER_SETPASS(MLD_LISTENER_DONE, &filt);
	ICMP6_FILTER_SETPASS(MLDV2_LISTENER_REPORT,&filt);
	if (setsockopt(mld_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) < 0)
		die("setsockopt(ICMP6_FILTER) failed");

	if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
		die("setsockopt(IPV6_RECVPKTINFO) failed");

	if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &on, sizeof(on)) < 0)
		die("setsockopt(IPV6_MULTICAST_HOPS) failed");

	if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) < 0)
		die("setsockopt(IPV6_MULTICAST_LOOP) failed");

	ctrl_buf = calloc(1, CTRL_BUF_SIZE);
	if (!ctrl_buf)
		die("malloc(CTRL_BUF) failed");

	send_buf = calloc(1, SEND_BUF_SIZE);
	if (!send_buf)
		die("malloc(SEND_BUF) failed");

	recv_buf = calloc(1, RECV_BUF_SIZE);
	if (!recv_buf)
		die("malloc(RECV_BUF) failed");

	log_debug("MLD initialised, socket: %i", mld_socket);

	return mld_socket;
}

void mld_bind(struct query_interface *qi)
{
	struct ipv6_mreq mreq = { 0 };

	mreq.ipv6mr_interface = qi->qi_ifindex;
	mreq.ipv6mr_multiaddr = allnodes_group;
	if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		die("setsockopt(IPV6_JOIN_GROUP) %s failed",
		    inet6_fmt(&mreq.ipv6mr_multiaddr));

	mreq.ipv6mr_multiaddr = allrouters_group;
	if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		die("setsockopt(IPV6_JOIN_GROUP) %s failed",
		    inet6_fmt(&mreq.ipv6mr_multiaddr));

	mreq.ipv6mr_multiaddr = allreports_group;
	if (setsockopt(mld_socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
		die("setsockopt(IPV6_JOIN_GROUP) %s failed",
		    inet6_fmt(&mreq.ipv6mr_multiaddr));

	/* SO_BINDTODEVICE does not receive leaves */
	/* bind() ll address does not receive leaves */
}

void mld_handle(void)
{
	struct msghdr rcvmsg = { 0 };
	struct iovec rcviov = { 0 };
	struct sockaddr_in6 recv_addr = { 0 };
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;

	struct in6_addr *src, *dst;
	struct mld_hdr *mld;
	ssize_t recvlen;
	ssize_t pktlen;
	uint8_t *pktbuf;
	unsigned int mld_version = 0;

	rcviov.iov_base = (caddr_t)recv_buf;
	rcviov.iov_len = RECV_BUF_SIZE;
	rcvmsg.msg_control = (caddr_t)ctrl_buf;
	rcvmsg.msg_controllen = CTRL_BUF_SIZE;
	rcvmsg.msg_name = &recv_addr;
	rcvmsg.msg_namelen = sizeof(recv_addr);
	rcvmsg.msg_iov = &rcviov;
	rcvmsg.msg_iovlen = 1;

	while ((recvlen = recvmsg(mld_socket, &rcvmsg, 0)) < 0) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return;

		log_error("recvmsg(%i) MLD failed: %s (%i)",
			  mld_socket, strerror(errno), errno);
		return;
	}

	pktlen = recvlen;
	pktbuf = recv_buf;

	if (pktlen < sizeof(struct mld_hdr)) {
		log_warn("received packet too short (%zu bytes) for MLD header", pktlen);
		log_dump(recv_buf, recvlen);
		return;
	}

	/* extract optional information via Advanced API */
	for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&rcvmsg); cm;
	     cm = (struct cmsghdr *) CMSG_NXTHDR(&rcvmsg, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *) (CMSG_DATA(cm));
			break;
		}
		/*
		 * In case of MLDv1, since RFC2710 does not mention whether to
		 * discard MLD packets with hop limit other than 1. Whereas in
		 * case of MLDv2, it should be discarded as is stated in
		 * draft-vida-mld-v2-08.txt section 6.2.
		 * Despite all for this application keeping eyes closed what
		 * relates to hop limit checking
		 */
	}

	if (!pi) {
		log_warn("failed to get Rx control information");
		return;
	}

	dst = &pi->ipi6_addr;
	src = &((struct sockaddr_in6 *)&recv_addr)->sin6_addr;

	mld = (struct mld_hdr *)pktbuf;

	/*
	 * MLD version of a multicast listener Query is determined as
	 * follow : MLDv1 query : recvlen = 24
	 *          MLDv2 query : recvlen >= 28
	 *          MLDv2 report type != MLDv1 report type
	 * Query messages that do not match any of the above conditions are ignored.
	 */
	switch (mld->mld_type)
	{
	case MLD_LISTENER_QUERY:
		if (pktlen == 24)
			mld_version = 1;
		if (pktlen >= 28) {
			mld_version = 2;
		}
		break;

	case MLD_LISTENER_DONE:
	case MLD_LISTENER_REPORT:
	case MLDV2_LISTENER_REPORT:
		break;

	default:
		/* This must be impossible since we set a type filter */
		log_warn("Got unknown ICMPV6 message type %x from %s to %s",
			 mld->mld_type, inet6_fmt(src), inet6_fmt(dst));
		log_dump(recv_buf, recvlen);
		return;
	}

	log_notice("RECV %-16s from %-26s to %-18s on %-15s",
		   mld_packet_kind(mld->mld_type, mld->mld_code, mld_version),
		   inet6_fmt(src), inet6_fmt(dst), get_ifname(pi->ipi6_ifindex));

	if (IN6_IS_ADDR_MC_NODELOCAL(&mld->mld_addr)) {
		log_warn("Got %s with an invalid scope: %s from %s",
			 mld_packet_kind(mld->mld_type, mld->mld_code, mld_version),
			 inet6_fmt(&mld->mld_addr), inet6_fmt(src));
	}

	if (!IN6_IS_ADDR_LINKLOCAL(src)) {
		/*
		 * RFC3590 allows the IPv6 unspecified address as the source
		 * address of MLD report and done messages.  However, as this
		 * same document says, this special rule is for snooping
		 * switches and the RFC requires routers to discard MLD packets
		 * with the unspecified source address.
		 */
		log_warn("Got %s from a non link local address: %s",
			 mld_packet_kind(mld->mld_type, mld->mld_code, mld_version),
			 inet6_fmt(src));
	}
}

int mld_emit(struct query_interface *qi, struct mld_query_params *qp)
{
	struct msghdr sndmsg = { 0 };
	struct iovec sndiov = { 0 };
	struct sockaddr_in6 send_addr = { 0 };
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pktinfo;
	struct in6_addr nulladdr = { 0 };

	struct mldv2_hdr *mld;
	size_t mldlen;
	size_t ctllen, hbhlen;
	ssize_t len;
	uint8_t *hbhbuf;
	unsigned int realnbr;
	unsigned short rtalert_code = htons(IP6_ALERT_MLD);
#ifdef HAVE_RFC3542
	int tmplen;
	void *optp = NULL;
#endif
	unsigned int mld_version = qp->version ? qp->version : 1;

	if (mld_version == 2)
		mldlen = sizeof(struct mldv2_hdr);
	else /* mld_version == 1 */
		mldlen = sizeof(struct mld_hdr);

	mld = (struct mldv2_hdr *)send_buf;
	mld->mld_type = MLD_LISTENER_QUERY;
	mld->mld_code = 0;
	mld->mld_addr = qp->group;
	if (mld_version == 2) {
		mld->mld_maxdelay = htons(codafloat(qp->response_time ? qp->response_time :
						    MLD6_QUERY_RESPONSE_INTERVAL, &realnbr, 3, 12));
		/* SFLAG:1, QRV:3 */
		mld->mld_rtval |= qp->router_suppress ? 0x08 : 0x00;
		mld->mld_rtval |= (qp->querier_robust ? qp->querier_robust :
				   MLD6_ROBUSTNESS_VARIABLE) & 0x07;
		mld->mld_qqi = codafloat(qp->querier_interval ? qp->querier_interval :
					 MLD6_QUERY_INTERVAL, &realnbr, 3, 4);
	} else { /* mld_version == 1 */
		mld->mld_maxdelay = htons(qp->response_time ? qp->response_time :
					  MLD6_QUERY_RESPONSE_INTERVAL);
	}
	mld->mld_cksum = 0;

	send_addr.sin6_family = AF_INET6;
	send_addr.sin6_addr = allnodes_group;
	send_addr.sin6_scope_id = qi->qi_ifindex; /* For link-local only */

	ctllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
#ifdef HAVE_RFC3542
	if ((hbhlen = inet6_opt_init(NULL, 0)) == -1)
		die("inet6_opt_init(0) failed");
	if ((hbhlen = inet6_opt_append(NULL, 0, hbhlen, IP6OPT_ROUTER_ALERT, 2, 2, NULL)) == -1)
		die("inet6_opt_append(0) failed");
	if ((hbhlen = inet6_opt_finish(NULL, 0, hbhlen)) == -1)
		die("inet6_opt_finish(0) failed");
	ctllen += CMSG_SPACE(hbhlen);
#else
	hbhlen = 8;
	ctllen += CMSG_SPACE(hbhlen);
#endif
	memset(ctrl_buf, 0, sizeof(ctllen));

	sndiov.iov_base = (caddr_t)send_buf;
	sndiov.iov_len = mldlen;
	sndmsg.msg_control = (caddr_t)ctrl_buf;
	sndmsg.msg_controllen = ctllen;
	sndmsg.msg_name = &send_addr;
	sndmsg.msg_namelen = sizeof(send_addr);
	sndmsg.msg_iov = &sndiov;
	sndmsg.msg_iovlen = 1;

	cmsg = CMSG_FIRSTHDR(&sndmsg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	memset(pktinfo, 0, sizeof(*pktinfo));
	pktinfo->ipi6_ifindex = qi->qi_ifindex;
	pktinfo->ipi6_addr = qi->qi_ip6addr ? *qi->qi_ip6addr : nulladdr;

	cmsg = CMSG_NXTHDR(&sndmsg, cmsg);
#ifdef HAVE_RFC3542
	cmsg->cmsg_len = CMSG_LEN(hbhlen);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPOPTS;
	hbhbuf = CMSG_DATA(cmsg);
	if ((tmplen = inet6_opt_init(hbhbuf, hbhlen)) == -1)
		die("inet6_opt_init(len = %d) failed", hbhlen);
	tmplen = inet6_opt_append(hbhbuf, hbhlen, tmplen,
				  IP6OPT_ROUTER_ALERT, 2, 2, &optp);
	if (tmplen == -1)
		die("inet6_opt_append(len = %d/%d) failed", tmplen, hbhlen);
	(void)inet6_opt_set_val(optp, 0, &rtalert_code, sizeof(rtalert_code));
	if (inet6_opt_finish(hbhbuf, hbhlen, tmplen) == -1)
		die("inet6_opt_finish(buf) failed");
#else
	cmsg->cmsg_len = CMSG_LEN(hbhlen);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPOPTS;
	hbhbuf = CMSG_DATA(cmsg);
	/* (2B wrap)(2B struct ip6_opt)(2B data)(2B wrap) */
	*((uint16_t *)&hbhbuf[0]) = 0; /* Initialization */
	*((uint8_t *)&hbhbuf[2]) = IP6OPT_ROUTER_ALERT;
	*((uint8_t *)&hbhbuf[3]) = IP6OPT_RTALERT_LEN - 2;
	*((uint16_t *)&hbhbuf[4]) = rtalert_code;
	*((uint16_t *)&hbhbuf[6]) = 1; /* Finalization */
#endif
	cmsg = CMSG_NXTHDR(&sndmsg, cmsg);

	do {
		len = sendmsg(mld_socket, &sndmsg, MSG_DONTROUTE);
	} while ((len < 0) && (errno == EINTR));
	if (len < 0) {
		log_error("sendmsg(%i) MLD failed: %s (%i)",
			  mld_socket, strerror(errno), errno);
		return -1;
	}

	log_notice("SENT MLD query on %s from %s to %s, len %zu",
		   qi->qi_ifname, inet6_fmt(&pktinfo->ipi6_addr),
		   inet6_fmt(&send_addr.sin6_addr), len);

	return 0;
}
