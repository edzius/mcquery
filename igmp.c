
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h> /* in_addr, IPPROTO_* */
#include <netinet/ip.h> /* ip */
#include <netinet/igmp.h> /* igmp, IGMP_* */

#include "logger.h"
#include "igmp.h"
#include "mcquery.h"

#define SEND_BUF_SIZE 128
#define CTRL_BUF_SIZE 128

static int igmp_socket;
static uint8_t *ctrl_buf;
static uint8_t *send_buf;

static uint32_t	allhosts_group;

void igmp_exit(void)
{
	close(igmp_socket);
	free(ctrl_buf);
	free(send_buf);

	log_debug("IGMP finished");
}

int igmp_init(void)
{
	int on = 1;

	allhosts_group = htonl(INADDR_ALLHOSTS_GROUP);

	igmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	if (igmp_socket < 0)
		die("socket(IGMP) failed");

	if (setsockopt(igmp_socket, SOL_IP, IP_PKTINFO, &on, sizeof(on)) < 0)
		die("setsockopt(IP_PKTINFO) failed");

	if (setsockopt(igmp_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
		die("setsockopt(IP_HDRINCL) failed");

	if (setsockopt(igmp_socket, IPPROTO_IP, IP_MULTICAST_TTL, &on, sizeof(on)) < 0)
		die("setsockopt(IP_MULTICAST_TTL) failed");

	if (setsockopt(igmp_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on)) < 0)
		die("setsockopt(IP_MULTICAST_LOOP) faiked");

	ctrl_buf = calloc(1, CTRL_BUF_SIZE);
	if (!ctrl_buf)
		die("malloc(CTRL_BUF) failed");

	send_buf = calloc(1, SEND_BUF_SIZE);
	if (!send_buf)
		die("malloc(SEND_BUF) failed");

	log_debug("IGMP initialised, socket: %i", igmp_socket);

	return igmp_socket;
}

int igmp_emit(struct query_interface *qi, struct igmp_query_params *qp)
{
	struct msghdr sndmsg = { 0 };
	struct iovec sndiov = { 0 };
	struct sockaddr_in send_addr = { 0 };
	struct cmsghdr *cmsg;
	struct in_pktinfo *pktinfo;

	struct ip *ip;
	struct igmpv3_query *igmp;
	uint8_t *ip_opt;
	size_t ip_len, igmp_len;
	size_t ctllen;
	ssize_t len;
	unsigned int igmp_code;
	unsigned int igmp_version = qp->version ? qp->version : 2;

	ip_len = sizeof(struct ip) + IP_EXTHDR_LEN;
	if (igmp_version == 3) {
		igmp_len = IGMP_V3_MINLEN;
	} else { /* igmp_version == 2 || igmp_version == 1 */
		igmp_len = IGMP_MINLEN;
	}

	ip = (struct ip *)send_buf;
	igmp = (struct igmpv3_query *)(send_buf + ip_len);

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
	/* Source address filled in when zero (raw(7)). */
	ip->ip_src.s_addr = qi->qi_ipaddr ? qi->qi_ipaddr->s_addr : 0;
	ip->ip_dst.s_addr = allhosts_group;

	/*
	 * RFC2113 IP Router Alert. Per spec this is required to
	 * force certain routers/switches to inspect this frame.
	 */
	ip_opt = (uint8_t *)(ip + 1);
	ip_opt[0] = IPOPT_RA;
	ip_opt[1] = 4;
	ip_opt[2] = 0;
	ip_opt[3] = 0;

	/* Ignored when IP_HDRINCL socket option is enabled.
	 * Still required to be set otherwise sendmsg() fails. */
	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.s_addr = allhosts_group;

	ctllen = CMSG_SPACE(sizeof(struct in_pktinfo));
	memset(ctrl_buf, 0, ctllen);

	sndiov.iov_base = (caddr_t)send_buf;
	sndiov.iov_len = ip_len + igmp_len;
	sndmsg.msg_control = (caddr_t)ctrl_buf;
	sndmsg.msg_controllen = ctllen;
	sndmsg.msg_name = &send_addr;
	sndmsg.msg_namelen = sizeof(send_addr);
	sndmsg.msg_iov = &sndiov;
	sndmsg.msg_iovlen = 1;

	cmsg = CMSG_FIRSTHDR(&sndmsg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
	pktinfo->ipi_ifindex = qi->qi_ifindex;
	/* Packet info addresses fields are ignored
	 * when IP_HDRINCL socket option is enabled. */
	/* pktinfo->ipi_addr = (in_addr_t)allhosts_group */
	/* pktinfo->ipi_spec_dst = *qi->qi_ipaddr */

	do {
		len = sendmsg(igmp_socket, &sndmsg, MSG_DONTROUTE);
	} while ((len < 0) && (errno == EINTR));
	if (len < 0) {
		log_error("sendmsg(%i) IGMP failed: %s (%i)",
			  igmp_socket, strerror(errno), errno);
		return -1;
	}

	log_notice("SENT IGMP query on %s from %s to %s, len %zu",
		   qi->qi_ifname, inet_fmt(ip->ip_src.s_addr),
		   inet_fmt(send_addr.sin_addr.s_addr), len);

	return 0;
}
