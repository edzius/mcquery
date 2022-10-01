
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "logger.h"
#include "mcquery.h"

struct mcq_opts {
	struct igmp_query_params *mc_igmp;
	struct mld_query_params *mc_mld;
	char mc_raw;
};

void igmp_exit(void);
int igmp_init(void);
int igmp_emit(struct query_interface *qi, struct igmp_query_params *qp);

void rawigmp_exit(void);
int rawigmp_init(void);
int rawigmp_emit(struct query_interface *qi, struct igmp_query_params *qp);

void mld_exit(void);
int mld_init(void);
int mld_emit(struct query_interface *qi, struct mld_query_params *qp);

void rawmld_exit(void);
int rawmld_init(void);
int rawmld_emit(struct query_interface *qi, struct mld_query_params *qp);

int log_verbose = 0;
static char *program = NULL;

static char *progname(char *arg0)
{
	char *nm;

	nm = strrchr(arg0, '/');
	if (nm)
		nm++;
	else
		nm = arg0;

	return nm;
}

static int usage(int code)
{
	printf("Usage: %s [-i INTERFACE] [-r] [igmp[:<version>[,<key>:<value>...]]] [mld[:<version>[,<key>:<value>...]]]\n"
	       "\n"
	       "Options:\n"
	       "  -h, --help               Show this help text\n"
	       "  -v, --verbose            Perform verbose operation\n"
	       "  -i, --interface <name>   Interface to use\n"
	       "  -r, --raw                Use RAW sockets\n"
	       "\n"
	       "Parameters:\n"
	       "  * igmp:<version>         IGMP version, allowed values: 1, 2, 3, default: 2\n"
	       "  * mld:<version>          MLD version, allowed values: 1, 2, default: 1\n"
	       "  * rt|respond:<time>      Maximal response time, default: 10 seconds\n"
	       "  * gr|group:<address>     Specific group to query, default: no group\n"
	       "  * rs|suppress:<state>    Router suppresion, allowed values 'y', 'n', default: n\n"
	       "  * qr|robust:<value>      Querier robustness value, default: 2\n"
	       "  * qi|interval:<value>    Querier interval value, default: 125 sec\n"
	       , program);
	return code;
}

static struct igmp_query_params * parse_igmp_params(const char *arg)
{
	static struct igmp_query_params igmp_params;
	char *tmp, *key, *val;

	memset(&igmp_params, 0, sizeof(igmp_params));
	if (!arg)
		return &igmp_params;

	errno = EINVAL;
	tmp = strdup(arg);
	key = strtok(tmp, ":");
	while (key && (val = strtok(NULL, ";,"))) {
		if (!strcmp(key, "igmp")) {
			igmp_params.version = atoi(val);
			if (igmp_params.version < 1 || igmp_params.version > 3)
				die("Invalid IGMP version provided: %s", val);
		} else if (!strcmp(key, "rt") || !strcmp(key, "respond")) {
			igmp_params.response_time = atoi(val);
		} else if (!strcmp(key, "gr") || !strcmp(key, "group")) {
			if (!inet_aton(val, &igmp_params.group) ||
			    !IN_MULTICAST(htonl(igmp_params.group.s_addr)))
				die("Invalid IGMP group address: %s", val);
		} else if (!strcmp(key, "rs") || !strcmp(key, "suppress")) {
			igmp_params.router_suppress = *val == 'y';
		} else if (!strcmp(key, "qr") || !strcmp(key, "robust")) {
			igmp_params.querier_robust = atoi(val);
		} else if (!strcmp(key, "qi") || !strcmp(key, "interval")) {
			igmp_params.querier_interval = atoi(val);
		}
		key = strtok(NULL, ":");
	}
	free(tmp);

	return &igmp_params;
}

static struct mld_query_params *parse_mld_params(const char *arg)
{
	static struct mld_query_params mld_params;
	char *tmp, *key, *val;

	memset(&mld_params, 0, sizeof(mld_params));
	if (!arg)
		return &mld_params;

	errno = EINVAL;
	tmp = strdup(arg);
	key = strtok(tmp, ":");
	while (key && (val = strtok(NULL, ";,"))) {
		if (!strcmp(key, "mld")) {
			mld_params.version = atoi(val);
			if (mld_params.version < 1 || mld_params.version > 2)
				die("Invalid MLD version provided: %s", val);
		} else if (!strcmp(key, "rt") || !strcmp(key, "respond")) {
			mld_params.response_time = atoi(val);
		} else if (!strcmp(key, "gr") || !strcmp(key, "group")) {
			if (inet_pton(AF_INET6, val, &mld_params.group) < 1 ||
			    !IN6_IS_ADDR_MULTICAST(mld_params.group.s6_addr))
				die("Invalid MLD group address: %s", val);
		} else if (!strcmp(key, "rs") || !strcmp(key, "suppress")) {
			mld_params.router_suppress = *val == 'y';
		} else if (!strcmp(key, "qr") || !strcmp(key, "robust")) {
			mld_params.querier_robust = atoi(val);
		} else if (!strcmp(key, "qi") || !strcmp(key, "interval")) {
			mld_params.querier_interval = atoi(val);
		}
		key = strtok(NULL, ":");
	}
	free(tmp);

	return &mld_params;
}

static void mcq_dump_opts(struct mcq_opts *o)
{
	if (o->mc_igmp) {
		log_debug("IGMP set"
			  "; version %i"
			  "; respond time %i"
			  "; group address %s"
			  "; router suppress %i"
			  "; querier robustness %i"
			  "; querier interval %i",
			  o->mc_igmp->version,
			  o->mc_igmp->response_time,
			  inet_ntoa(o->mc_igmp->group),
			  o->mc_igmp->router_suppress,
			  o->mc_igmp->querier_robust,
			  o->mc_igmp->querier_interval);

	} else {
		log_debug("IGMP not set");
	}

	if (o->mc_mld) {
		char group_address[48];
		inet_ntop(AF_INET6, &o->mc_mld->group, group_address, sizeof(group_address));
		log_debug("MLD set"
			  "; version %i"
			  "; respond time %i"
			  "; group address %s"
			  "; router suppress %i"
			  "; querier robustness %i"
			  "; querier interval %i",
			  o->mc_mld->version,
			  o->mc_mld->response_time,
			  group_address,
			  o->mc_mld->router_suppress,
			  o->mc_mld->querier_robust,
			  o->mc_mld->querier_interval);
	} else {
		log_debug("MLD not set");
	}
}

void mcq_send(struct query_interface *qi, struct mcq_opts *o)
{
	if (o->mc_raw) {
		if (o->mc_igmp) {
			rawigmp_init();
			rawigmp_emit(qi, o->mc_igmp);
			rawigmp_exit();
		}
		if (o->mc_mld) {
			rawmld_init();
			rawmld_emit(qi, o->mc_mld);
			rawmld_exit();
		}
	} else {
		if (o->mc_igmp) {
			igmp_init();
			igmp_emit(qi, o->mc_igmp);
			igmp_exit();
		}
		if (o->mc_mld) {
			mld_init();
			mld_emit(qi, o->mc_mld);
			mld_exit();
		}
	}
}

int main(int argc, char *argv[])
{
	int ch, i;
	char *opt_ifname = NULL;
	struct mcq_opts opts = { 0 };
	struct query_interface *qi = NULL;

	struct option long_options[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "raw", no_argument, NULL, 'r' },
		{ "interface", required_argument, NULL, 'i' },
		{ NULL, 0, NULL, 0 }
	};

	setlinebuf(stderr);

	program = progname(argv[0]);
	while ((ch = getopt_long(argc, argv, "hvri:", long_options, NULL)) != EOF) {
		switch (ch) {
		case 'h':
			return usage(0);

		case 'v':
			log_verbose++;
			break;

		case 'i':
			opt_ifname = optarg;
			break;

		case 'r':
			opts.mc_raw = 1;
			break;

		default:
			return usage(1);
		}
	}

	for (i = optind; i < argc; i++) {
		if (!strncmp(argv[i], "igmp", 4))
			opts.mc_igmp = parse_igmp_params(argv[i]);
		else if (!strncmp(argv[i], "mld", 3))
			opts.mc_mld = parse_mld_params(argv[i]);
		else
			return usage(1);
	}

	if (!opts.mc_igmp && !opts.mc_mld) {
		opts.mc_igmp = parse_igmp_params(NULL);
		opts.mc_mld = parse_mld_params(NULL);
	}

	if (opt_ifname) {
		qi = iface_get(opt_ifname);
		if (!qi)
			die("Failed to find %s network interface", opt_ifname);
	} else {
		qi = iface_first();
		if (!qi)
			die("Failed to get network interface");
	}

	mcq_dump_opts(&opts);

	mcq_send(qi, &opts);

	return 0;
}
