#ifndef _MLD_H
#define _MLD_H

#include <netinet/in.h> /* in6_addr */
#include <netinet/icmp6.h> /* icmp6_hdr, MLD_LISTENER_* */

struct mldv2_hdr {      /* MLDv2 Header */
	struct icmp6_hdr mld_icmp6_hdr;     /* Standard ICMP header */
	struct in6_addr mld_addr;   /* Multicast Address */
	uint8_t         mld_rtval;  /* Resv+S+QRV */
	uint8_t         mld_qqi;    /* QQIC */
	uint16_t        mld_numsrc; /* Number of Sources */
	struct in6_addr mld_src[0]; /* Sources Addresses List */
};

#ifndef IN6ADDR_LINKLOCAL_ALLNODES_INIT
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
        {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#endif
#ifndef IN6ADDR_LINKLOCAL_ALLROUTERS_INIT
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
        {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}
#endif
#ifndef IN6ADDR_LINKLOCAL_ALLREPORTS_INIT
#define IN6ADDR_LINKLOCAL_ALLREPORTS_INIT \
        {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16 }}}
#endif

#ifndef MLD_LISTENER_QUERY
#define MLD_LISTENER_QUERY 130
#endif
#ifndef MLD_LISTENER_REPORT
#define MLD_LISTENER_REPORT 131
#endif
#ifndef MLD_LISTENER_DONE
#define MLD_LISTENER_DONE 132
#endif
#ifndef MLDV2_LISTENER_REPORT
#define MLDV2_LISTENER_REPORT 143
#endif

#ifndef IP6OPT_RTALERT_LEN
#define IP6OPT_RTALERT_LEN 4
#endif

/* Each extension header is an integer multiple of 8 octets long, RFC 2460 */
#define IP6_EXTHDR_LEN 8

#define MLD6_QUERY_RESPONSE_INTERVAL 10000 /* in milliseconds */
#define MLD6_QUERY_INTERVAL 125 /* in seconds */
#define MLD6_ROBUSTNESS_VARIABLE 2

static inline char *mld_packet_kind(int type, int code, int version)
{
	static char unknown[60];

	switch (type) {
	case MLD_LISTENER_QUERY:
		if (version == 1)               return "MLDv1 Query";
		else if (version == 2)          return "MLDv2 Query";
		else                            return "MLD Query";
	case MLD_LISTENER_DONE:                 return "MLD Done";
	case MLD_LISTENER_REPORT:               return "MLDv1 Report";
	case MLDV2_LISTENER_REPORT:             return "MLDv2 Report";
	default:
		snprintf(unknown, sizeof(unknown),
			 "UNKNOWN ICMPv6 message: type = 0x%02x, code = 0x%02x ",
			 type, code);
		return unknown;
	}
}

#endif // _MLD_H
