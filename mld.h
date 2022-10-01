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

#ifndef IP6OPT_RTALERT_LEN
#define IP6OPT_RTALERT_LEN 4
#endif

/* Each extension header is an integer multiple of 8 octets long, RFC 2460 */
#define IP6_EXTHDR_LEN 8

#define MLD6_QUERY_RESPONSE_INTERVAL 10000 /* in milliseconds */
#define MLD6_QUERY_INTERVAL 125 /* in seconds */
#define MLD6_ROBUSTNESS_VARIABLE 2

#endif // _MLD_H
