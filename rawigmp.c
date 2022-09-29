
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h> /* ETH* */
#include <netinet/in.h> /* in_addr, IPPROTO_* */
#include <netinet/ip.h> /* ip */
#include <netinet/igmp.h> /* igmp, IGMP_* */
#include <linux/filter.h>
#include <linux/if_packet.h> /* sockaddr_ll */

#include "logger.h"
#include "igmp.h"
#include "mcquery.h"

#define RECV_BUF_SIZE 1024
#define SEND_BUF_SIZE 128
#define CTRL_BUF_SIZE 128

static int rawigmp_socket;
static uint8_t *ctrl_buf;
static uint8_t *recv_buf;
static uint8_t *send_buf;

static struct sock_filter code[] = {
#ifndef USE_COOKED_SOCKET
	/* tcpdump -dd ip proto \\igmp */
	{ 0x28, 0, 0, 0x0000000c }, /* Ethernet type */
	{ 0x15, 0, 3, 0x00000800 }, /* ETHERTYPE_IP */
	{ 0x30, 0, 0, 0x00000017 }, /* IP Protocol */
	{ 0x15, 0, 1, 0x00000002 }, /* IPPROTO_IGMP */
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
#else
	/* tcpdump -dd ip proto \\igmp */
	/* Adjusted filter match IP header */
	{ 0x30, 0, 0, 0x00000009 }, /* IP Protocol */
	{ 0x15, 0, 1, 0x00000002 }, /* IPPROTO_IGMP */
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
#endif
};

void rawigmp_exit(void)
{
	close(rawigmp_socket);
	free(ctrl_buf);
	free(send_buf);
	free(recv_buf);

	log_debug("RAW IGMP finished");
}

int rawigmp_init(void)
{
	int on = 1;
	struct sock_fprog bpf = {0};

#ifndef USE_COOKED_SOCKET
	rawigmp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_IP));
#else
	rawigmp_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_IP));
#endif
	if (rawigmp_socket < 0)
		die("socket(RAW) failed");

	bpf.len = sizeof(code)/sizeof(struct sock_filter);
	bpf.filter = code;
	if (setsockopt(rawigmp_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		die("setsockopt(SO_ATTACH_FILTER) failed");

	if (setsockopt(rawigmp_socket, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on)) < 0)
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

	log_debug("RAW IGMP initialised, socket: %i", rawigmp_socket);

	return rawigmp_socket;
}

void rawigmp_bind(struct query_interface *qi)
{
	struct sockaddr_ll addr = {0};

	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = qi->qi_ifindex;
	if (bind(rawigmp_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("bind() failed");
}

void rawigmp_handle(void)
{
	struct msghdr rcvmsg = { 0 };
	struct iovec rcviov = { 0 };
	struct sockaddr_ll recv_addr = { 0 };
	struct cmsghdr *cm;
	struct tpacket_auxdata *pa = NULL;

	struct ip *ip;
	struct igmp *igmp;
	uint32_t src, dst;
	ssize_t recvlen;
	ssize_t pktlen;
	uint8_t *pktbuf;
	uint32_t ipdatalen, iphdrlen, igmpdatalen;
	unsigned int igmp_version = 0;

	rcviov.iov_base = (caddr_t)recv_buf;
	rcviov.iov_len = RECV_BUF_SIZE;
	rcvmsg.msg_control = (caddr_t)ctrl_buf;
	rcvmsg.msg_controllen = CTRL_BUF_SIZE;
	rcvmsg.msg_name = &recv_addr;
	rcvmsg.msg_namelen = sizeof(recv_addr);
	rcvmsg.msg_iov = &rcviov;
	rcvmsg.msg_iovlen = 1;

	while ((recvlen = recvmsg(rawigmp_socket, &rcvmsg, 0)) < 0) {
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN)
			return;

		log_error("recvmsg(%i) IGMP failed: %s (%i)",
			  rawigmp_socket, strerror(errno), errno);
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

	if (pktlen < sizeof(struct ip)) {
		log_warn("received packet too short (%zu bytes) for IP header", pktlen);
		log_dump(recv_buf, recvlen);
		return;
	}

	ip = (struct ip *)pktbuf;
	src = ip->ip_src.s_addr;
	dst = ip->ip_dst.s_addr;

	if (ip->ip_p != IPPROTO_IGMP) {
		log_debug("received packet with non-IGMP IP protocol %i", ip->ip_p);
		return;
	}

	iphdrlen  = ip->ip_hl << 2;
	ipdatalen = ntohs(ip->ip_len) - iphdrlen;

	/* Read ethernet packet may have padding bytes, therefore
	 * recvlen would may be greater than header and payload. */
	if (pktlen < (size_t)(iphdrlen + ipdatalen)) {
		log_warn("received packet from %s shorter (%zu bytes) than hdr+data length (%d+%d)",
			 inet_fmt(src), recvlen, iphdrlen, ipdatalen);
		log_dump(recv_buf, recvlen);
		return;
	}

	igmp = (struct igmp *)(pktbuf + iphdrlen);
	igmpdatalen = ipdatalen - IGMP_MINLEN;

	if (igmpdatalen < 0) {
		log_warn("received IP data field too short (%u bytes) for IGMP, from %s",
			 ipdatalen, inet_fmt(src));
		log_dump(recv_buf, recvlen);
		return;
	}

	/* Initial IGMP sanity checking */
	switch (igmp->igmp_type) {
	case IGMP_MEMBERSHIP_QUERY:
		/* RFC 3376:7.1 */
		if (ipdatalen == 8) {
			if (igmp->igmp_code == 0) {
				igmp_version = 1;
			} else {
				igmp_version = 2;
			}
		} else if (ipdatalen >= 12) {
			igmp_version = 3;
		} else {
			log_warn("Received invalid IGMP query: Max Resp Code = %d, length = %d",
				 igmp->igmp_code, ipdatalen);
			log_dump(recv_buf, recvlen);
			return;
		}
		break;

	case IGMP_V1_MEMBERSHIP_REPORT:
	case IGMP_V2_MEMBERSHIP_REPORT:
	case IGMP_V2_LEAVE_GROUP:
		break;

	case IGMP_V3_MEMBERSHIP_REPORT:
		if (igmpdatalen < IGMP_V3_REPORT_MINLEN) {
			log_warn("Too short IGMP v3 Membership report: igmpdatalen(%d) < MIN(%d)",
				 igmpdatalen, IGMP_V3_REPORT_MINLEN);
			log_dump(recv_buf, recvlen);
			return;
		}
		break;

	default:
		log_warn("Got unknown IGMP message type %x from %s to %s",
			 igmp->igmp_type, inet_fmt(src), inet_fmt(dst));
		log_dump(recv_buf, recvlen);
		return;
	}

	log_notice("RECV %-16s from %-26s to %-18s on %-15s from %s",
		   igmp_packet_kind(igmp->igmp_type, igmp->igmp_code, igmp_version),
		   inet_fmt(src), inet_fmt(dst), get_ifname(recv_addr.sll_ifindex),
		   hwaddr_fmt(recv_addr.sll_addr));
}

int rawigmp_emit(struct query_interface *qi, struct igmp_query_params *qp)
{
	const uint8_t allhosts_mac[] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 };
	const uint32_t allhosts_group = htonl(INADDR_ALLHOSTS_GROUP);

	struct msghdr sndmsg = { 0 };
	struct iovec sndiov = { 0 };
	struct sockaddr_ll send_addr = { 0 };

	struct ether_header *eth;
	struct ip *ip;
	struct igmpv3_query *igmp;
	uint8_t *ip_opt;
	size_t eth_len, ip_len, igmp_len;
	ssize_t len;
	unsigned int igmp_code;
	unsigned int igmp_version = qp->version ? qp->version : 2;

	eth_len = 0;
	ip_len = sizeof(struct ip) + IP_EXTHDR_LEN;
	if (igmp_version == 3) {
		igmp_len = IGMP_V3_MINLEN;
	} else { /* igmp_version == 2 || igmp_version == 1 */
		igmp_len = IGMP_MINLEN;
	}

#ifndef USE_COOKED_SOCKET
	eth_len = sizeof(struct ether_header);
	eth = (struct ether_header *)send_buf;
#endif
	ip = (struct ip *)(send_buf + eth_len);
	igmp = (struct igmpv3_query *)(send_buf + eth_len + ip_len);

	/*
	 * IGMP version to send depends on the compatibility mode of the
	 * interface:
	 *  - IGMPv3: routers MUST include querier robustness var value and
	 *    IGMP floating point encoded query interval code.
	 *  - IGMPv2: routers MUST send Periodic Queries truncated at the
	 *    Group Address field (i.e., 8 bytes long).
	 *  - IGMPv1: routers MUST send Periodic Queries with a Max Response
	 *    Time of 0
	 */
	igmp_code = (qp->response_time ? qp->response_time :
		     IGMP_QUERY_RESPONSE_INTERVAL) * IGMP_TIMER_SCALE;
	igmp->igmp_type = IGMP_MEMBERSHIP_QUERY;
	*((uint32_t *)&igmp->igmp_group) = qp->group.s_addr;
	if (igmp_version == 3) {
		igmp->igmp_code = igmp_floating_point(igmp_code);
		igmp->igmp_qqic = igmp_floating_point(qp->querier_interval ?
						      qp->querier_interval :
						      IGMP_QUERY_INTERVAL_DEFAULT);
		igmp->igmp_qrv = qp->querier_robust ?
			qp->querier_robust : IGMP_ROBUSTNESS_DEFAULT;
		igmp->igmp_suppress = qp->router_suppress ? 1 : 0;
	} else if (igmp_version == 2) {
		igmp->igmp_code = igmp_code;
	} else { /* igmp_version == 1 */
		igmp->igmp_code = 0;
	}
	igmp->igmp_cksum = 0; /* Initial checksum reset */
	igmp->igmp_cksum = inet_cksum((uint16_t *)igmp, igmp_len);

	ip->ip_v = IPVERSION;
	ip->ip_hl = (sizeof(struct ip) + IP_EXTHDR_LEN) >> 2;
	ip->ip_tos = 0xc0; /* Internet Control */
	ip->ip_ttl = 1;
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_len = htons(ip_len + igmp_len);
	ip->ip_off = 0;
	ip->ip_id = getpid() & 0xFFFF;
	ip->ip_src.s_addr = 0;
	ip->ip_dst.s_addr = (in_addr_t)allhosts_group;
	ip->ip_sum = 0; /* Initial checksum reset */
	ip->ip_sum = inet_cksum((uint16_t *)ip, ip_len);

	/*
	 * RFC2113 IP Router Alert. Per spec this is required to
	 * force certain routers/switches to inspect this frame.
	 */
	ip_opt = (uint8_t *)(ip + 1);
	ip_opt[0] = IPOPT_RA;
	ip_opt[1] = 4;
	ip_opt[2] = 0;
	ip_opt[3] = 0;

#ifndef USE_COOKED_SOCKET
	memcpy(eth->ether_dhost, allhosts_mac, sizeof(eth->ether_dhost));
	memcpy(eth->ether_shost, qi->qi_macaddr, sizeof(eth->ether_dhost));
	eth->ether_type = htons(ETH_P_IP);
#endif

	send_addr.sll_family = AF_PACKET;
	send_addr.sll_protocol = htons(ETH_P_IP);
	send_addr.sll_ifindex = qi->qi_ifindex;
	send_addr.sll_halen = ETHER_ADDR_LEN;
	memcpy(send_addr.sll_addr, allhosts_mac, ETHER_ADDR_LEN);

	sndiov.iov_base = (caddr_t)send_buf;
	sndiov.iov_len = eth_len + ip_len + igmp_len;
	sndmsg.msg_name = &send_addr;
	sndmsg.msg_namelen = sizeof(send_addr);
	sndmsg.msg_iov = &sndiov;
	sndmsg.msg_iovlen = 1;

	do {
		len = sendmsg(rawigmp_socket, &sndmsg, MSG_DONTROUTE);
	} while ((len < 0) && (errno == EINTR));
	if (len < 0) {
		log_error("sendmsg(%i) IGMP failed: %s (%i)",
			  rawigmp_socket, strerror(errno), errno);
		return -1;
	}

	log_notice("SENT IGMP query on %s from %s to %s, len %zu",
		   qi->qi_ifname, inet_fmt(ip->ip_src.s_addr),
		   inet_fmt(ip->ip_dst.s_addr), len);

	return 0;
}
