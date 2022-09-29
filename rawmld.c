
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h> /* ETH* */
#include <netinet/in.h> /* in6_addr, IPPROTO_* */
#include <netinet/ip6.h> /* ip6_hdr */
#include <netinet/icmp6.h> /* icmp6_hdr, mld_hdr */
#include <linux/filter.h>
#include <linux/if_packet.h> /* sockaddr_ll */

#include "logger.h"
#include "mld.h"
#include "mcquery.h"

#define RECV_BUF_SIZE 1024
#define SEND_BUF_SIZE 128
#define CTRL_BUF_SIZE 128

static int rawmld_socket;
static uint8_t *ctrl_buf;
static uint8_t *send_buf;
static uint8_t *recv_buf;

static struct sock_filter code[] = {
#ifndef USE_COOKED_SOCKET
	/* tcpdump -dd icmp6 .. +fixed HBH option inst. */
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 6, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 }, /* ICMPv6 Next header */
	{ 0x15, 3, 0, 0x0000003a }, /* IPPROTO_ICMPV6 */
	{ 0x15, 0, 3, 0x00000000 }, /* IPPROTO_HOPOPTS */
	{ 0x30, 0, 0, 0x00000036 }, /* ICMPv6 HBH Next header */
	{ 0x15, 0, 1, 0x0000003a }, /* IPPROTO_ICMPV6 */
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
#else
	/* tcpdump -dd icmp6 .. +fixed HBH option inst. */
	/* Adjusted filter match IPv6 header */
	{ 0x30, 0, 0, 0x00000006 }, /* ICMPv6 Next header */
	{ 0x15, 3, 0, 0x0000003a }, /* IPPROTO_ICMPV6 */
	{ 0x15, 0, 3, 0x00000000 }, /* IPPROTO_HOPOPTS */
	{ 0x30, 0, 0, 0x00000028 }, /* ICMPv6 HBH Next header */
	{ 0x15, 0, 1, 0x0000003a }, /* IPPROTO_ICMPV6 */
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
#endif
};

void rawmld_exit(void)
{
	close(rawmld_socket);
	free(ctrl_buf);
	free(send_buf);
	free(recv_buf);

	log_debug("RAW MLD finished");
}

int rawmld_init(void)
{
	int on = 1;
	struct sock_fprog bpf = {0};

#ifndef USE_COOKED_SOCKET
	rawmld_socket = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IPV6));
#else
	rawmld_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_IPV6));
#endif
	if (rawmld_socket < 0)
		die("socket(RAW) failed");

	bpf.len = sizeof(code)/sizeof(struct sock_filter);
	bpf.filter = code;
	/* Socket filter is relevant only for Rx, */
	if (setsockopt(rawmld_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		die("setsockopt(SO_ATTACH_FILTER) failed");

	/* Socket filter is relevant only for Rx, */
	if (setsockopt(rawmld_socket, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on)) < 0)
		die("setsockopt(PACKET_AUXDATA) failed");

	ctrl_buf = calloc(1, CTRL_BUF_SIZE);
	if (!ctrl_buf)
		die("malloc(CTRL_BUF) failed");

	send_buf = calloc(1, SEND_BUF_SIZE);
	if (!send_buf)
		die("malloc(SEND_BUF) failed");

	recv_buf = calloc(1, RECV_BUF_SIZE);
	if (!recv_buf)
		die("malloc(RECV_BUF) failed");

	log_debug("RAW MLD initialised, socket: %i", rawmld_socket);

	return rawmld_socket;
}

void rawmld_bind(struct query_interface *qi)
{
	struct sockaddr_ll addr = {0};

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = qi->qi_ifindex;
	if (bind(rawmld_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("bind() failed");
}

void rawmld_handle(void)
{
	struct msghdr rcvmsg = { 0 };
	struct iovec rcviov = { 0 };
	struct sockaddr_ll recv_addr = { 0 };
	struct cmsghdr *cm;
	struct tpacket_auxdata *pa = NULL;

	struct ip6_hdr *ip6;
	struct ip6_hbh *ip6hbh;
	struct in6_addr *src, *dst;
	struct mld_hdr *mld;
	ssize_t recvlen;
	ssize_t pktlen;
	uint8_t *pktbuf;
	uint32_t ip6optlen = 0, ip6datalen, ip6datatype;
	unsigned int mld_version = 0;

	rcviov.iov_base = (caddr_t)recv_buf;
	rcviov.iov_len = RECV_BUF_SIZE;
	rcvmsg.msg_control = (caddr_t)ctrl_buf;
	rcvmsg.msg_controllen = CTRL_BUF_SIZE;
	rcvmsg.msg_name = &recv_addr;
	rcvmsg.msg_namelen = sizeof(recv_addr);
	rcvmsg.msg_iov = &rcviov;
	rcvmsg.msg_iovlen = 1;

	while ((recvlen = recvmsg(rawmld_socket, &rcvmsg, 0)) < 0) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return;

		log_error("recvmsg(%i) MLD failed: %s (%i)",
			  rawmld_socket, strerror(errno), errno);
		return;
	}

	/* extract optional information via Advanced API */
	for (cm = (struct cmsghdr *) CMSG_FIRSTHDR(&rcvmsg); cm;
	     cm = (struct cmsghdr *) CMSG_NXTHDR(&rcvmsg, cm)) {
		if (cm->cmsg_level == SOL_PACKET && cm->cmsg_type == PACKET_AUXDATA &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct tpacket_auxdata))) {
			pa = (struct tpacket_auxdata *) CMSG_DATA(cm);
			break;
		}
	}

	if (!pa) {
		log_warn("failed to get Rx control information");
		return;
	}

	/* Skip VLAN tagged packets; this is the case when
	 * link interface receives VLAN tagged packets. */
	if (pa->tp_vlan_tci) {
		return;
	}

	pktlen = recvlen - pa->tp_net;
	pktbuf = recv_buf + pa->tp_net;

	if (pktlen < sizeof(struct ip6_hdr)) {
		log_warn("received packet too short (%zu bytes) for IPv6 header", pktlen);
		log_dump(recv_buf, recvlen);
		return;
	}

	ip6 = (struct ip6_hdr *)pktbuf;
	src = &ip6->ip6_src;
	dst = &ip6->ip6_dst;

	ip6datatype = ip6->ip6_nxt;
	ip6datalen = ntohs(ip6->ip6_plen);

	if (pktlen != (size_t)(sizeof(*ip6) + ip6datalen)) {
		log_warn("received packet from %s shorter (%zu bytes) than hdr+data length (%d+%d)",
			 inet6_fmt(src), pktlen, (int)sizeof(*ip6), ip6datalen);
		log_dump(recv_buf, recvlen);
		return;
	}

	/*
	 * In case of MLDv1, since RFC2710 does not mention whether to
	 * discard MLD packets with hop limit other than 1. Whereas in
	 * case of MLDv2, it should be discarded as is stated in
	 * draft-vida-mld-v2-08.txt section 6.2.
	 */
	/* Neighbour discovery seems to be using hop limit > 1,
	 * however we have no interes in message of this type. */
	if (ip6->ip6_hlim > 1) {
		log_debug("received IPv6 packet from %s has too many hops %i",
			  inet6_fmt(src), ip6->ip6_hlim);
		return;
	}

	/* XXX: assuming IPv6 to have only single extended header */
	if (ip6->ip6_nxt == IPPROTO_HOPOPTS) {
		ip6hbh = (struct ip6_hbh *)(pktbuf + sizeof(*ip6));
		ip6optlen = (ip6hbh->ip6h_len + 1) * 8;
		ip6datatype = ip6hbh->ip6h_nxt;
	}

	if (ip6datatype != IPPROTO_ICMPV6) {
		log_debug("received IPv6 packet from %s with non-MLD type %i",
			  inet6_fmt(src), ip6datatype);
		log_dump(recv_buf, recvlen);
		return;
	}

	if (pktlen < (sizeof(*ip6) + ip6optlen + sizeof(struct mld_hdr))) {
		log_warn("received IPv6 packet too short (%zu bytes) for MLD message", pktlen);
		log_dump(recv_buf, recvlen);
		return;
	}

	mld = (struct mld_hdr *)(pktbuf + sizeof(*ip6) + ip6optlen);

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

	log_notice("RECV %-16s from %-26s to %-18s on %-15s from %s",
		   mld_packet_kind(mld->mld_type, mld->mld_code, mld_version),
		   inet6_fmt(src), inet6_fmt(dst), get_ifname(recv_addr.sll_ifindex),
		   hwaddr_fmt(recv_addr.sll_addr));

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

int rawmld_emit(struct query_interface *qi, struct mld_query_params *qp)
{
	const struct in6_addr allnodes_group = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
	const unsigned char allhosts_mac[] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };

	struct msghdr sndmsg = { 0 };
	struct iovec sndiov = { 0 };
	struct sockaddr_ll send_addr = { 0 };

	struct ether_header *eth;
	struct ip6_hdr *ip;
	struct ip6_hbh *iphbh;
	struct ip6_opt *ipopt;
	struct mldv2_hdr *mld;
	size_t eth_len, ip_len, mld_len;
	ssize_t len;
	unsigned int realnbr;
	unsigned int mld_version = qp->version ? qp->version : 1;

	eth_len = 0;
	ip_len = sizeof(struct ip6_hdr) + IP6_EXTHDR_LEN;
	if (mld_version == 2)
		mld_len = sizeof(struct mldv2_hdr);
	else /* mld_version == 1 */
		mld_len = sizeof(struct mld_hdr);

#ifndef USE_COOKED_SOCKET
	eth_len = sizeof(struct ether_header);
	eth = (struct ether_header *)send_buf;

	memcpy(eth->ether_dhost, allhosts_mac, sizeof(eth->ether_dhost));
	memcpy(eth->ether_shost, qi->qi_macaddr, sizeof(eth->ether_dhost));
	eth->ether_type = htons(ETH_P_IPV6);
#endif
	ip = (struct ip6_hdr *)(send_buf + eth_len);
	mld = (struct mldv2_hdr *)(send_buf + eth_len + ip_len);

	/* IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) */
	ip->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
	/* Payload length (16 bits): IPv6 HBH + MLD header */
	ip->ip6_plen = htons(IP6_EXTHDR_LEN + mld_len);
	/* Next header (8 bits) */
	ip->ip6_nxt = IPPROTO_HOPOPTS;
	/* Hop limit (8 bits) */
	ip->ip6_hops = 1;
	/* Destination IPv6 address (128 bits) */
	ip->ip6_dst = allnodes_group;
	/* Source IPv6 address (128 bits) */
	ip->ip6_src = qi->qi_ip6addr ? *qi->qi_ip6addr : in6addr_any;

	iphbh = (struct ip6_hbh *)(ip + 1);
	iphbh->ip6h_nxt = IPPROTO_ICMPV6;
	iphbh->ip6h_len = 0;

	ipopt = (struct ip6_opt *)(iphbh + 1);
	ipopt->ip6o_type = IP6OPT_ROUTER_ALERT;
	ipopt->ip6o_len = IP6OPT_RTALERT_LEN - sizeof(struct ip6_hbh);
	*((unsigned short *)(ipopt + 1)) = (unsigned short)IP6_ALERT_MLD;

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
	mld->mld_cksum = inet6_cksum(ip, IPPROTO_ICMPV6, mld, mld_len);

	send_addr.sll_family = AF_PACKET;
	send_addr.sll_protocol = htons(ETH_P_IPV6);
	send_addr.sll_ifindex = qi->qi_ifindex;
	send_addr.sll_halen = ETHER_ADDR_LEN;
	memcpy(send_addr.sll_addr, allhosts_mac, ETHER_ADDR_LEN);

	sndiov.iov_base = (caddr_t)send_buf;
	sndiov.iov_len = eth_len + ip_len + mld_len;
	sndmsg.msg_name = &send_addr;
	sndmsg.msg_namelen = sizeof(send_addr);
	sndmsg.msg_iov = &sndiov;
	sndmsg.msg_iovlen = 1;

	do {
		len = sendmsg(rawmld_socket, &sndmsg, MSG_DONTROUTE);
	} while ((len < 0) && (errno == EINTR));
	if (len < 0) {
		log_error("sendmsg(%i) MLD failed: %s (%i)",
			  rawmld_socket, strerror(errno), errno);
		return -1;
	}

	log_notice("SENT MLD query on %s from %s to %s, len %zu",
		   qi->qi_ifname, inet6_fmt(&ip->ip6_src),
		   inet6_fmt(&ip->ip6_dst), len);

	return 0;
}
