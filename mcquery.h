#ifndef _MCQUERY_H
#define _MCQUERY_H

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#ifndef MAC2STR
#define MAC2STR(a) (uint8_t)(a)[0], (uint8_t)(a)[1], (uint8_t)(a)[2], \
                   (uint8_t)(a)[3], (uint8_t)(a)[4], (uint8_t)(a)[5]
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MACSTRLEN 18
#endif

#ifndef IP2STR
#define IP2STR(a) (uint8_t)(a)[0], (uint8_t)(a)[1], \
                  (uint8_t)(a)[2], (uint8_t)(a)[3]
#define IPSTR "%u.%u.%u.%u"
#define IPSTRLEN 16
#endif

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

struct query_interface {
	char qi_ifname[IFNAMSIZ];
	unsigned int qi_ifindex;
	unsigned char qi_macaddr[IFHWADDRLEN];
	struct in_addr *qi_ipaddr;
	struct in6_addr *qi_ip6addr;
};

char *get_ifname(int ifindex);
char *hwaddr_fmt(unsigned char addr[]);
char *inet_fmt(uint32_t addr);
char *inet6_fmt(struct in6_addr *addr);
int inet_cksum(void *addr, unsigned int len);
int inet6_cksum(struct ip6_hdr *iphdr, unsigned char proto,
		void *ulhdr, unsigned int ullen);
uint8_t igmp_floating_point(unsigned int mantissa);
unsigned int codafloat(unsigned int nbr, unsigned int *realnbr,
		       unsigned int sizeexp, unsigned int sizemant);
struct query_interface *iface_get(char *ifname);
struct query_interface *iface_first(void);

#endif // _MCQUERY_H
