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

/*
 * The IGMPv2 <netinet/in.h> defines INADDR_ALLRTRS_GROUP, but earlier
 * ones don't, so we define it conditionally here.
 */
#ifndef INADDR_ALLRTRS_GROUP
#define INADDR_ALLRTRS_GROUP    ((in_addr_t)0xe0000002) /* 224.0.0.2 */
#endif
#ifndef INADDR_ALLRPTS_GROUP
#define INADDR_ALLRPTS_GROUP    ((in_addr_t)0xe0000016) /* 224.0.0.22, IGMPv3 */
#endif

/*
 * The original multicast releases defined
 * IGMP_HOST_{MEMBERSHIP_QUERY,MEMBERSHIP_REPORT,NEW_MEMBERSHIP_REPORT
 *   ,LEAVE_MESSAGE}.  Later releases removed the HOST and inserted
 * the IGMP version number.  NetBSD inserted the version number in
 * a different way.  mrouted uses the new names, so we #define them
 * to the old ones if needed.
 */
#if !defined(IGMP_MEMBERSHIP_QUERY) && defined(IGMP_HOST_MEMBERSHIP_QUERY)
#define IGMP_MEMBERSHIP_QUERY		IGMP_HOST_MEMBERSHIP_QUERY
#define IGMP_V2_LEAVE_GROUP		IGMP_HOST_LEAVE_MESSAGE
#endif
#ifndef IGMP_V1_MEMBERSHIP_REPORT
#ifdef  IGMP_HOST_MEMBERSHIP_REPORT
#define IGMP_V1_MEMBERSHIP_REPORT	IGMP_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT	IGMP_HOST_NEW_MEMBERSHIP_REPORT
#endif
#ifdef  IGMP_v1_HOST_MEMBERSHIP_REPORT
#define IGMP_V1_MEMBERSHIP_REPORT	IGMP_v1_HOST_MEMBERSHIP_REPORT
#define IGMP_V2_MEMBERSHIP_REPORT	IGMP_v2_HOST_MEMBERSHIP_REPORT
#endif
#endif
#if !defined(IGMP_V3_MEMBERSHIP_REPORT) && defined(IGMP_v3_HOST_MEMBERSHIP_REPORT)
#define IGMP_V3_MEMBERSHIP_REPORT	IGMP_v3_HOST_MEMBERSHIP_REPORT
#else
#define IGMP_V3_MEMBERSHIP_REPORT	0x22    /* Ver. 3 membership report */
#endif

#define IGMP_QUERY_INTERVAL_DEFAULT 125
#define IGMP_ROBUSTNESS_DEFAULT 2
#define IGMP_QUERY_RESPONSE_INTERVAL 10
#define IGMP_TIMER_SCALE 10

#define IGMP_V3_MINLEN IGMP_MINLEN + 4
#define IGMP_V3_REPORT_MINLEN 8

#define IP_EXTHDR_LEN 4 /* IP option header */

static inline char *igmp_packet_kind(int type, int code, int version)
{
	static char unknown[60];

	switch (type) {
	case IGMP_MEMBERSHIP_QUERY:
		if (version == 1)               return "IGMPv1 Query";
		else if (version == 2)          return "IGMPv2 Query";
		else if (version == 3)          return "IGMPv3 Query";
		else                            return "IGMP Query";
	case IGMP_V1_MEMBERSHIP_REPORT:         return "IGMPv1 Report";
	case IGMP_V2_MEMBERSHIP_REPORT:         return "IGMPv2 Report";
	case IGMP_V3_MEMBERSHIP_REPORT:         return "IGMPv3 Report";
	case IGMP_V2_LEAVE_GROUP:               return "IGMP Leave";
	default:
		snprintf(unknown, sizeof(unknown),
			 "UNKNOWN IGMP message: type = 0x%02x, code = 0x%02x",
			 type, code);
		return unknown;
	}
}

#endif // _IGMP_H
