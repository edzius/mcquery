#ifndef _MCQUERY_H
#define _MCQUERY_H

#include <netinet/in.h>

struct igmp_query_params {
	unsigned char version;
	unsigned char response_time;
	struct in_addr group;
	unsigned char router_suppress;
	unsigned char querier_robust;
	unsigned char querier_interval;
};

struct mld_query_params {
	unsigned char version;
	unsigned char response_time;
	struct in6_addr group;
	unsigned char router_suppress;
	unsigned char querier_robust;
	unsigned char querier_interval;
};

#endif // _MCQUERY_H
