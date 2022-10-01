#ifndef _IGMP_H
#define _IGMP_H

#include <netinet/in.h> /* INADDR_* */
#include <netinet/igmp.h> /* IGMP_* */

struct igmpv3_query {
	uint8_t  igmp_type;
	uint8_t  igmp_code;
	uint16_t igmp_cksum;
	uint32_t igmp_group;
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
	uint8_t  igmp_qrv:3,
		 igmp_suppress:1,
		 resv:4;
#else
	uint8_t  resv:4,
		 igmp_suppress:1,
		 igmp_qrv:3;
#endif
	uint8_t  igmp_qqic;
	uint16_t igmp_nsrcs;
	uint32_t igmp_srcs[0];
};

#define IGMP_QUERY_INTERVAL_DEFAULT 125
#define IGMP_ROBUSTNESS_DEFAULT 2
#define IGMP_QUERY_RESPONSE_INTERVAL 10
#define IGMP_TIMER_SCALE 10

#define IGMP_V3_MINLEN IGMP_MINLEN + 4

#define IP_EXTHDR_LEN 4 /* IP option header */

#endif // _IGMP_H
