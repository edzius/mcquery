
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

#define SEND_BUF_SIZE 128
#define CTRL_BUF_SIZE 128

static int rawmld_socket;
static uint8_t *send_buf;

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
	free(send_buf);

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

	send_buf = calloc(1, SEND_BUF_SIZE);
	if (!send_buf)
		die("malloc(SEND_BUF) failed");

	log_debug("RAW MLD initialised, socket: %i", rawmld_socket);

	return rawmld_socket;
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
