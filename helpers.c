
#include <dirent.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "logger.h"
#include "mcquery.h"

#define SYSFS_PATH "/sys/class/net"

char *get_ifname(int ifindex)
{
	static char ifname[IFNAMSIZ];

	return if_indextoname(ifindex, ifname);
}

/*
 * Convert 6 byte MAC struct into printable MAC address string.
 */
char *hwaddr_fmt(unsigned char addr[])
{
	static char macbuf[4][MACSTRLEN];
	static int macround = 0;
	char *cp;
	unsigned char *a = (unsigned char *)addr;

	/* Static buffer selection */
	macround = (macround + 1) & 3;
	cp = macbuf[macround];

	sprintf(cp, MACSTR, MAC2STR(a));

	return cp;
}

/*
 * Convert 4 byte integer into printable IP address string.
 */
char *inet_fmt(uint32_t addr)
{
	static char ipbuf[4][16];
	static int ipround = 0;
	char *cp;
	uint8_t *a = (uint8_t *)&addr;

	/* Static buffer selection */
	ipround = (ipround + 1) & 3;
	cp = ipbuf[ipround];

	sprintf(cp, IPSTR, IP2STR(a));

	return cp;
}

/*
 * Convert a 128bit IPv6 address into a printable string.
 */
char *inet6_fmt(struct in6_addr *addr)
{
	struct sockaddr_in6 sa6 = { 0 };
	static char ip6buf[4][40];
	static int ip6round = 0;
	int flags = NI_NUMERICHOST;
	char *cp;

	/* Static buffer selection */
	ip6round = (ip6round + 1) & 3;
	cp = ip6buf[ip6round];

	sa6.sin6_family = AF_INET6;
	sa6.sin6_addr = *addr;

	/*
	 * construct sin6_scope_id for link-scope addresses from embedded link IDs.
	 * XXX: this should be hidden from applications.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&sa6.sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sa6.sin6_addr)) {
		sa6.sin6_scope_id = sa6.sin6_addr.s6_addr[2] << 8 | sa6.sin6_addr.s6_addr[3];
		sa6.sin6_addr.s6_addr[2] = sa6.sin6_addr.s6_addr[3] = 0;
	}

	getnameinfo((struct sockaddr *)&sa6, sizeof(sa6), cp, 40, NULL, 0, flags);

	return cp;
}

int inet_cksum(void *addr, unsigned int len)
{
	int nleft = (int)len;
	uint16_t *w = addr;
	uint16_t answer = 0;
	int32_t sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(uint8_t *) (&answer) = *(uint8_t *)w;
		sum += answer;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);                 /* add carry */
	answer = ~sum;                      /* truncate to 16 bits */

	return answer;
}

/* IPv6 checksum includes pseudo-header and upper layer header
 * and payload. For more details refer to RFC2460 Section 8.1. */
int inet6_cksum(struct ip6_hdr *iphdr, unsigned char proto,
		void *ulhdr, unsigned int ullen)
{
	char buf[4096];
	char *ptr = buf;

	ptr = buf;
	/* Source address */
	memcpy(ptr, &iphdr->ip6_src, sizeof(iphdr->ip6_src));
	ptr += sizeof (iphdr->ip6_src);
	/* Destination address */
	memcpy(ptr, &iphdr->ip6_dst, sizeof(iphdr->ip6_dst));
	ptr += sizeof(iphdr->ip6_dst);
	/* Upper-Layer Packet length */
	*((unsigned int *)ptr) = htonl(ullen);
	ptr += sizeof(ullen);
	/* Zero fields */
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	*ptr = 0; ptr++;
	/* Next header */
	*ptr = proto; ptr++;
	/* Upper layer header */
	memcpy(ptr, ulhdr, ullen);
	ptr += ullen;

	return inet_cksum((uint16_t *)buf, ptr - buf);
}

/*
 * RFC-3376 states that Max Resp Code (MRC) and Querier's Query Interval Code
 * (QQIC) should be presented in floating point value if their value exceeds
 * 128. The following formula is used by IGMPv3 clients to calculate the
 * actual value of the floating point:
 *
 *       0 1 2 3 4 5 6 7
 *      +-+-+-+-+-+-+-+-+
 *      |1| exp | mant  |
 *      +-+-+-+-+-+-+-+-+
 *
 *   QQI / MRT = (mant | 0x10) << (exp + 3)
 *
 * This requires us to find the largest set (fls) bit in the 15-bit number
 * and set the exponent based on its index in the bits 15-8. ie.
 *
 *   exponent 0: igmp_fls(0000 0000 1000 0010)
 *   exponent 5: igmp_fls(0001 0000 0000 0000)
 *   exponent 7: igmp_fls(0111 0101 0000 0000)
 *
 * and set that as the exponent. The mantissa is set to the last 4 bits
 * remaining after the (3 + exponent) shifts to the right.
 *
 * Note!
 * The numbers 31744-32767 are the maximum we can present with floating
 * point that has an exponent of 3 and a mantissa of 4. After this the
 * implementation just wraps around back to zero.
 */
uint8_t igmp_floating_point(unsigned int mantissa)
{
	unsigned int exponent;

	/* Wrap around numbers larger than 2^15, since those can not be
	 * presented with 7-bit floating point. */
	mantissa &= 0x00007FFF;

	/* If top 8 bits are zero. */
	if (!(mantissa & 0x00007F80))
		return mantissa;

	/* Shift the mantissa and mark this code floating point. */
	mantissa >>= 3;
	/* At this point the actual exponent (bits 7-5) are still 0, but the
	 * exponent might be incremented below. */
	exponent = 0x00000080;

	/* If bits 7-4 are not zero. */
	if (mantissa & 0x00000F00) {
		mantissa >>= 4;
		/* The index of largest set bit is at least 4. */
		exponent  |= 0x00000040;
	}

	/* If bits 7-6 OR bits 3-2 are not zero. */
	if (mantissa & 0x000000C0) {
		mantissa >>= 2;
		/* The index of largest set bit is atleast 6 if we shifted the
		 * mantissa earlier or atleast 2 if we did not shift it. */
		exponent |= 0x00000020;
	}

	/* If bit 7 OR bit 3 OR bit 1 is not zero. */
	if (mantissa & 0x00000020) {
		mantissa >>= 1;
		/* The index of largest set bit is atleast 7 if we shifted the
		 * mantissa two times earlier or atleast 3 if we shifted the
		 * mantissa last time or atleast 1 if we did not shift it. */
		exponent |= 0x00000010;
	}

	return exponent | (mantissa & 0x0000000F);
}

/*
 * given a number, an exp. size in bits and a mantisse size in bits, return
 * the coded number value according to the code described in
 * draft-vida-mld-v2-08.txt
 * used to compute the Maximum Response Code (exp=3bit, mant=12bit)
 * and the Querier Query interval Code (exp=3bit, mant=4 bit)
 * format  : |1|...exp...|...mant...|
 * if the number isn't representable there is a difference between realnbr
 * and nbr if the number is too big return the max code value with a warning
 */
unsigned int codafloat(unsigned int nbr, unsigned int *realnbr,
		       unsigned int sizeexp, unsigned int sizemant)
{
	unsigned int mask = 0x1;
	unsigned int max = 0x0;
	unsigned int exp = 1;   /*exp value */
	unsigned int tmax;      /*max code value */
	unsigned int mantmask = 1;      /*mantisse mask */
	unsigned int onebit = 1;
	unsigned int mant;
	uint16_t code = 1;     /* code */
	int i;

	/* compute maximal exp value */
	for (i = 1; i < sizeexp; i++)
		exp = (exp << 1) | 1;

	/* maximum size of this number in bits (after decoding) */
	tmax = exp + 3 + sizemant + 1;

	/* minimum value of this number */
	code <<= sizeexp + sizemant;
	mask <<= tmax - 1;

	/* maximum value of this number + a mantisse masque */
	for (i = 0; i <= sizemant; i++)
		max = max | mask >> i;
	for (i = 0; i < sizemant; i++)
		mantmask = mantmask | (onebit << i);

	/* not in coded number, so just return the given number as it is */
	if (nbr < code) {
		code = *realnbr = nbr;
		return code;
	}

	/* overflowed, so just return the possible max value */
	if (nbr > max) {
		*realnbr = max;
		return codafloat(max, realnbr, sizeexp, sizemant);
	}

	/* calculate the float number */
	while (!(nbr & mask)) {
		mask >>= 1;
		tmax--;
	}
	exp = tmax - (sizemant + 1);
	mant = nbr >> exp;
	exp -= 3;

	/* build code */
	mant &= mantmask;
	code |= mant;
	code |= exp << sizemant;

	/* compute effective value (draft-vida-mld-v2-08.txt p.11) */
	onebit <<= sizemant;
	*realnbr = (mant | onebit) << (exp + 3);
	return code;
}

struct query_interface *iface_get(char *ifname)
{
	static struct query_interface qi = { 0 };
	static struct in_addr in4addr;
	static struct in6_addr in6addr;
	struct sockaddr_in *sin4 = NULL;
	struct sockaddr_in6 *sin6 = NULL;
	struct ifaddrs *ifaddr, *ifa;
	struct ifreq ifr = { 0 };
	static int sfd;
	int found = 0;

	if (!sfd)
		sfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sfd == -1)
		die("Failed to open ioctl socket");

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	strncpy(qi.qi_ifname, ifname, sizeof(qi.qi_ifname));

	if (ioctl(sfd, SIOCGIFINDEX, &ifr) < 0) {
		log_debug("Failed to get interface index: %s (%i)",
			  strerror(errno), errno);
		return NULL;
	}
	qi.qi_ifindex = ifr.ifr_ifindex;

	if (ioctl(sfd, SIOCGIFHWADDR, &ifr) < 0) {
		log_debug("Failed to get interfaces HW addr: %s (%i)",
			  strerror(errno), errno);
		return 0;
	}
	memcpy(qi.qi_macaddr, ifr.ifr_hwaddr.sa_data, sizeof(qi.qi_macaddr));

	/* More appropriate way to retrieve IPv6 addresses
	 * would be ask for them via netlink, however doing
	 * this way makes things a bit less complicated. */
	if (getifaddrs(&ifaddr) == -1) {
		freeifaddrs(ifaddr);
		log_debug("Failed to get interface addresses: %s (%i)",
			  strerror(errno), errno);
		return NULL;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname))
			continue;

		found = 1;
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
			if (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				continue;
			in6addr = sin6->sin6_addr;
		} else if (ifa->ifa_addr->sa_family == AF_INET) {
			sin4 = (struct sockaddr_in *)ifa->ifa_addr;
			in4addr = sin4->sin_addr;
		}
	}

	freeifaddrs(ifaddr);

	if (!found)
		return NULL;

	qi.qi_ipaddr = sin4 ? &in4addr : NULL;
	qi.qi_ip6addr = sin6 ? &in6addr : NULL;

	log_debug("Resolved %s, index %i, MAC %s, IPv4 %s, IPv6 %s",
		  qi.qi_ifname, qi.qi_ifindex, hwaddr_fmt(qi.qi_macaddr),
		  qi.qi_ipaddr ? inet_fmt(*((int *)qi.qi_ipaddr)) : "N/A",
		  qi.qi_ip6addr ? inet6_fmt(qi.qi_ip6addr) : "N/A");

	return &qi;
}

struct query_interface *iface_first(void)
{
	FILE *fp;
	DIR *dp;
	char ifname[IFNAMSIZ];
	char path_buf[128];
	char *path_ptr;
	unsigned int flags;
	struct dirent *entry;

	if ((dp = opendir(SYSFS_PATH)) == NULL) {
		log_debug("opendir() failed");
		return NULL;
	}

	path_ptr = path_buf + sprintf(path_buf, "%s/", SYSFS_PATH);

	while ((entry = readdir(dp)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		sprintf(path_ptr, "%s/flags", entry->d_name);

		if ((fp = fopen(path_buf, "r")) == NULL) {
			log_debug("fopen() failed");
			continue;
		}
		if (fscanf(fp, "0x%x", &flags) < 1) {
			log_debug("fscanf() failed");
			fclose(fp);
			continue;
		}
		fclose(fp);

		if (flags & IFF_LOOPBACK)
			continue;

		if ((flags & (IFF_UP | IFF_MULTICAST)) != (IFF_UP | IFF_MULTICAST))
			continue;

		strncpy(ifname, entry->d_name, sizeof(ifname));
		break;
	}

	closedir(dp);

	if (!entry)
		return NULL;

	return iface_get(ifname);
}
