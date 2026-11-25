// SPDX-License-Identifier: GPL-2.0-only
/*
 * netifd-stub: a minimal stand-in for OpenWrt's netifd, for the odhcpd network lab (LAB.md).
 *
 * It provides what odhcpd needs from netifd: the ubus object "network.interface" with the
 * "dump" method and an "interface.update" notification to its subscribers whenever an
 * interface changes. Like netifd, it puts the interfaces' addresses on their devices and
 * hands out /64s (ip6assign) of the ULA prefix and of delegated prefixes to its interfaces.
 *
 * Interfaces come from a JSON file (-c):
 *   { "ula_prefix": "fd00:1::/48",
 *     "interfaces": {
 *       "lan": { "device": "lan", "proto": "static", "ipaddr": [ "192.168.1.1/24" ],
 *                "ip6addr": [ ... ], "ip6assign": 64, "ip6hint": 1 },
 *       "wan6": { "device": "wan", "proto": "dhcpv6" } } }
 * Static interfaces are up from the start. The others are reported by the lab's DHCP client
 * scripts with "update" (as netifd's protocol handlers do with notify_proto):
 *   ubus call network.interface update '{ "interface": "wan6", "up": true,
 *     "ipv6-address": [ { "address": "...", "mask": 64, "preferred": 3600, "valid": 7200 } ],
 *     "ipv6-prefix": [ { "address": "2001:db8:100:200::", "mask": 56, ... } ],
 *     "route": [ { "target": "::", "mask": 0, "nexthop": "fe80::1" } ] }'
 * and "down" ({ "interface": "wan6" }). Not implemented: anything else netifd does.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubus.h>

#define MAX_ASSIGNED 16

struct prefix {
	struct in6_addr addr;
	int len;
	unsigned preferred, valid;	/* lifetimes in seconds, 0 = forever */
};

struct iface {
	struct list_head list;
	char *name, *device, *proto;
	int ip6assign, ip6hint;
	bool is_static, up;
	struct blob_attr *config;	/* the interface's JSON config */
	struct blob_attr *dynamic;	/* the last "update" for it */
	struct prefix assigned[MAX_ASSIGNED];	/* /64s (etc.) currently on the device */
	int n_assigned;
};

extern char **environ;

static LIST_HEAD(ifaces);
static struct ubus_context *ctx;
static struct blob_buf b;
static struct prefix ula;
static bool have_ula;

static void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logmsg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "netifd-stub: ");
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

/* Run a command (argv, no shell) and wait for it */
static int run(char *const argv[])
{
	pid_t pid;
	int status;

	if (posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ))
		return -1;
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static bool parse_prefix(const char *s, struct prefix *p)
{
	char buf[INET6_ADDRSTRLEN + 4], *slash;

	snprintf(buf, sizeof(buf), "%s", s);
	slash = strchr(buf, '/');
	if (!slash)
		return false;
	*slash = 0;
	p->len = atoi(slash + 1);
	p->preferred = p->valid = 0;
	return p->len >= 0 && p->len <= 128 && inet_pton(AF_INET6, buf, &p->addr) == 1;
}

/* The idx-th subprefix of length len within p (netifd's ip6assign/ip6hint) */
static bool subprefix(const struct prefix *p, int len, unsigned idx, struct prefix *out)
{
	if (len < p->len || len > 64 || (len - p->len < 32 && idx >= (1U << (len - p->len))))
		return false;

	*out = *p;
	out->len = len;
	/* the subnet bits sit in the upper 64 bits; set them, clear the rest */
	uint64_t hi = 0;
	for (int i = 0; i < 8; i++)
		hi = (hi << 8) | p->addr.s6_addr[i];
	uint64_t keep = p->len ? ~0ULL << (64 - p->len) : 0;
	hi = (hi & keep) | ((uint64_t)idx << (64 - len));
	for (int i = 7; i >= 0; i--, hi >>= 8)
		out->addr.s6_addr[i] = hi & 0xff;
	memset(&out->addr.s6_addr[8], 0, 8);
	return true;
}

static void ip_addr(const char *op, const char *family, const char *addr, int len,
		    const char *dev, unsigned preferred, unsigned valid)
{
	char cidr[INET6_ADDRSTRLEN + 8], pl[16], vl[16];
	char *argv[16] = { "ip", (char *)family, "addr", (char *)op, cidr, "dev", (char *)dev };
	int n = 7;

	snprintf(cidr, sizeof(cidr), "%s/%d", addr, len);
	if (valid && !strcmp(op, "replace")) {
		snprintf(pl, sizeof(pl), "%u", preferred);
		snprintf(vl, sizeof(vl), "%u", valid);
		argv[n++] = "preferred_lft";
		argv[n++] = pl;
		argv[n++] = "valid_lft";
		argv[n++] = vl;
	}
	argv[n] = NULL;
	if (run(argv))
		logmsg("ip %s addr %s %s dev %s failed", family, op, cidr, dev);
}

/* Static addresses of an interface (ipaddr/ip6addr lists) */
static void apply_static(struct iface *ifc)
{
	static const struct blobmsg_policy pol[2] = {
		{ .name = "ipaddr", .type = BLOBMSG_TYPE_ARRAY },
		{ .name = "ip6addr", .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[2], *cur;
	size_t rem;

	blobmsg_parse(pol, 2, tb, blobmsg_data(ifc->config), blobmsg_data_len(ifc->config));
	for (int f = 0; f < 2; f++) {
		if (!tb[f])
			continue;
		blobmsg_for_each_attr(cur, tb[f], rem) {
			char a[INET6_ADDRSTRLEN + 8], *slash;

			snprintf(a, sizeof(a), "%s", blobmsg_get_string(cur));
			slash = strchr(a, '/');
			if (!slash)
				continue;
			*slash = 0;
			ip_addr("replace", f ? "-6" : "-4", a, atoi(slash + 1), ifc->device, 0, 0);
		}
	}
}

enum { ADDR_ADDRESS, ADDR_MASK, ADDR_PREFERRED, ADDR_VALID, ADDR_MAX };
static const struct blobmsg_policy addr_policy[ADDR_MAX] = {
	[ADDR_ADDRESS] = { .name = "address", .type = BLOBMSG_TYPE_STRING },
	[ADDR_MASK] = { .name = "mask", .type = BLOBMSG_TYPE_INT32 },
	[ADDR_PREFERRED] = { .name = "preferred", .type = BLOBMSG_TYPE_INT32 },
	[ADDR_VALID] = { .name = "valid", .type = BLOBMSG_TYPE_INT32 },
};

enum { DYN_INTERFACE, DYN_UP, DYN_ADDR4, DYN_ADDR6, DYN_PREFIX6, DYN_ROUTE, DYN_MAX };
static const struct blobmsg_policy dyn_policy[DYN_MAX] = {
	[DYN_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[DYN_UP] = { .name = "up", .type = BLOBMSG_TYPE_BOOL },
	[DYN_ADDR4] = { .name = "ipv4-address", .type = BLOBMSG_TYPE_ARRAY },
	[DYN_ADDR6] = { .name = "ipv6-address", .type = BLOBMSG_TYPE_ARRAY },
	[DYN_PREFIX6] = { .name = "ipv6-prefix", .type = BLOBMSG_TYPE_ARRAY },
	[DYN_ROUTE] = { .name = "route", .type = BLOBMSG_TYPE_ARRAY },
};

/* Addresses and routes a client script reported for a dynamic interface */
static void apply_dynamic(struct iface *ifc, bool remove)
{
	static const struct blobmsg_policy route_policy[3] = {
		{ .name = "target", .type = BLOBMSG_TYPE_STRING },
		{ .name = "mask", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "nexthop", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[DYN_MAX], *cur;
	size_t rem;

	if (!ifc->dynamic)
		return;

	blobmsg_parse(dyn_policy, DYN_MAX, tb, blob_data(ifc->dynamic), blob_len(ifc->dynamic));
	for (int f = DYN_ADDR4; f <= DYN_ADDR6; f++) {
		if (!tb[f])
			continue;
		blobmsg_for_each_attr(cur, tb[f], rem) {
			struct blob_attr *a[ADDR_MAX];

			blobmsg_parse(addr_policy, ADDR_MAX, a, blobmsg_data(cur), blobmsg_data_len(cur));
			if (!a[ADDR_ADDRESS] || !a[ADDR_MASK])
				continue;
			ip_addr(remove ? "del" : "replace", f == DYN_ADDR4 ? "-4" : "-6",
				blobmsg_get_string(a[ADDR_ADDRESS]), blobmsg_get_u32(a[ADDR_MASK]),
				ifc->device,
				a[ADDR_PREFERRED] ? blobmsg_get_u32(a[ADDR_PREFERRED]) : 0,
				a[ADDR_VALID] ? blobmsg_get_u32(a[ADDR_VALID]) : 0);
		}
	}
	if (!tb[DYN_ROUTE] || remove)
		return;
	blobmsg_for_each_attr(cur, tb[DYN_ROUTE], rem) {
		struct blob_attr *r[3];
		char target[INET6_ADDRSTRLEN + 8];

		blobmsg_parse(route_policy, 3, r, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!r[0] || !r[1])
			continue;
		snprintf(target, sizeof(target), "%s/%u", blobmsg_get_string(r[0]), blobmsg_get_u32(r[1]));
		char *argv[] = { "ip", strchr(target, ':') ? "-6" : "-4", "route", "replace", target,
				 r[2] ? "via" : "dev", r[2] ? blobmsg_get_string(r[2]) : ifc->device,
				 r[2] ? "dev" : NULL, r[2] ? ifc->device : NULL, NULL };
		if (run(argv))
			logmsg("ip route replace %s on %s failed", target, ifc->device);
	}
}

/* All prefixes interfaces can get /64s (etc.) of: the ULA prefix and delegated prefixes */
static int collect_sources(struct prefix *src, int max)
{
	struct iface *ifc;
	int n = 0;

	if (have_ula)
		src[n++] = ula;

	list_for_each_entry(ifc, &ifaces, list) {
		struct blob_attr *tb[DYN_MAX], *cur;
		size_t rem;

		if (!ifc->up || !ifc->dynamic)
			continue;
		blobmsg_parse(dyn_policy, DYN_MAX, tb, blob_data(ifc->dynamic), blob_len(ifc->dynamic));
		if (!tb[DYN_PREFIX6])
			continue;
		blobmsg_for_each_attr(cur, tb[DYN_PREFIX6], rem) {
			struct blob_attr *a[ADDR_MAX];
			struct prefix p;

			blobmsg_parse(addr_policy, ADDR_MAX, a, blobmsg_data(cur), blobmsg_data_len(cur));
			if (!a[ADDR_ADDRESS] || !a[ADDR_MASK] || n >= max ||
			    inet_pton(AF_INET6, blobmsg_get_string(a[ADDR_ADDRESS]), &p.addr) != 1)
				continue;
			p.len = blobmsg_get_u32(a[ADDR_MASK]);
			p.preferred = a[ADDR_PREFERRED] ? blobmsg_get_u32(a[ADDR_PREFERRED]) : 0;
			p.valid = a[ADDR_VALID] ? blobmsg_get_u32(a[ADDR_VALID]) : 0;
			src[n++] = p;
		}
	}
	return n;
}

/* netifd-like ip6assign: each interface gets its hinted subprefix of every source prefix */
static bool reassign(struct iface *ifc)
{
	struct prefix src[MAX_ASSIGNED], want[MAX_ASSIGNED];
	int nsrc = collect_sources(src, MAX_ASSIGNED), nwant = 0;
	bool changed = false;

	if (ifc->ip6assign && ifc->up) {
		for (int i = 0; i < nsrc && nwant < MAX_ASSIGNED; i++)
			if (subprefix(&src[i], ifc->ip6assign, ifc->ip6hint, &want[nwant]))
				nwant++;
	}

	/* drop what is no longer wanted */
	for (int i = 0; i < ifc->n_assigned; i++) {
		bool keep = false;
		char a[INET6_ADDRSTRLEN];

		for (int j = 0; j < nwant; j++)
			keep |= !memcmp(&want[j].addr, &ifc->assigned[i].addr, 16) &&
				want[j].len == ifc->assigned[i].len;
		if (keep)
			continue;
		struct in6_addr host = ifc->assigned[i].addr;
		host.s6_addr[15] |= 1;
		inet_ntop(AF_INET6, &host, a, sizeof(a));
		ip_addr("del", "-6", a, ifc->assigned[i].len, ifc->device, 0, 0);
		changed = true;
	}

	/* (re)add the wanted ones, with the source prefix's lifetimes */
	for (int j = 0; j < nwant; j++) {
		char a[INET6_ADDRSTRLEN];
		struct in6_addr host = want[j].addr;
		bool had = false;

		for (int i = 0; i < ifc->n_assigned; i++)
			had |= !memcmp(&want[j].addr, &ifc->assigned[i].addr, 16) &&
			       want[j].len == ifc->assigned[i].len &&
			       want[j].valid == ifc->assigned[i].valid;
		host.s6_addr[15] |= 1;
		inet_ntop(AF_INET6, &host, a, sizeof(a));
		ip_addr("replace", "-6", a, want[j].len, ifc->device, want[j].preferred, want[j].valid);
		changed |= !had;
	}

	memcpy(ifc->assigned, want, sizeof(want[0]) * nwant);
	ifc->n_assigned = nwant;
	return changed;
}

static void notify(struct iface *ifc);

static void reassign_all(void)
{
	struct iface *ifc;

	list_for_each_entry(ifc, &ifaces, list)
		if (reassign(ifc))
			notify(ifc);
}

static void put_prefix(const struct prefix *p, const char *name)
{
	char a[INET6_ADDRSTRLEN];
	void *t = blobmsg_open_table(&b, name);

	inet_ntop(AF_INET6, &p->addr, a, sizeof(a));
	blobmsg_add_string(&b, "address", a);
	blobmsg_add_u32(&b, "mask", p->len);
	if (p->valid) {
		blobmsg_add_u32(&b, "preferred", p->preferred);
		blobmsg_add_u32(&b, "valid", p->valid);
	}
	blobmsg_close_table(&b, t);
}

/* One interface as netifd's dump/status reports it (the parts odhcpd and the lab look at) */
static void put_iface(struct iface *ifc)
{
	struct blob_attr *tb[DYN_MAX];
	void *t;

	blobmsg_add_string(&b, "interface", ifc->name);
	blobmsg_add_u8(&b, "up", ifc->up);
	blobmsg_add_string(&b, "proto", ifc->proto);
	blobmsg_add_string(&b, "device", ifc->device);
	if (ifc->up)
		blobmsg_add_string(&b, "l3_device", ifc->device);

	memset(tb, 0, sizeof(tb));
	if (ifc->dynamic)
		blobmsg_parse(dyn_policy, DYN_MAX, tb, blob_data(ifc->dynamic), blob_len(ifc->dynamic));
	if (tb[DYN_ADDR4])
		blobmsg_add_blob(&b, tb[DYN_ADDR4]);
	if (tb[DYN_ADDR6])
		blobmsg_add_blob(&b, tb[DYN_ADDR6]);
	if (tb[DYN_PREFIX6] && ifc->up)
		blobmsg_add_blob(&b, tb[DYN_PREFIX6]);
	else
		blobmsg_close_array(&b, blobmsg_open_array(&b, "ipv6-prefix"));

	t = blobmsg_open_array(&b, "ipv6-prefix-assignment");
	for (int i = 0; i < ifc->n_assigned; i++)
		put_prefix(&ifc->assigned[i], NULL);
	blobmsg_close_array(&b, t);

	blobmsg_close_table(&b, blobmsg_open_table(&b, "data"));
}

static struct ubus_object_type iface_type;
static struct ubus_object iface_obj;

static void notify(struct iface *ifc)
{
	struct blob_buf nb = {};

	blob_buf_init(&nb, 0);
	blobmsg_add_string(&nb, "interface", ifc->name);
	ubus_notify(ctx, &iface_obj, "interface.update", nb.head, -1);
	blob_buf_free(&nb);
	logmsg("interface %s updated (up=%d, %d assigned prefixes)", ifc->name, ifc->up,
	       ifc->n_assigned);
}

static struct iface *find_iface(const char *name)
{
	struct iface *ifc;

	list_for_each_entry(ifc, &ifaces, list)
		if (!strcmp(ifc->name, name))
			return ifc;
	return NULL;
}

static int handle_dump(struct ubus_context *c, struct ubus_object *obj, struct ubus_request_data *req,
		       const char *method, struct blob_attr *msg)
{
	struct iface *ifc;
	void *a;

	blob_buf_init(&b, 0);
	a = blobmsg_open_array(&b, "interface");
	list_for_each_entry(ifc, &ifaces, list) {
		void *t = blobmsg_open_table(&b, NULL);

		put_iface(ifc);
		blobmsg_close_table(&b, t);
	}
	blobmsg_close_array(&b, a);
	ubus_send_reply(c, req, b.head);
	return 0;
}

static int handle_update(struct ubus_context *c, struct ubus_object *obj, struct ubus_request_data *req,
			 const char *method, struct blob_attr *msg)
{
	struct blob_attr *tb[DYN_MAX];
	struct iface *ifc;
	bool down = !strcmp(method, "down");

	blobmsg_parse(dyn_policy, DYN_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[DYN_INTERFACE] || !(ifc = find_iface(blobmsg_get_string(tb[DYN_INTERFACE]))))
		return UBUS_STATUS_NOT_FOUND;
	if (ifc->is_static)
		return UBUS_STATUS_NOT_SUPPORTED;

	/* replace the reported state: remove the old addresses first */
	apply_dynamic(ifc, true);
	free(ifc->dynamic);
	ifc->dynamic = down ? NULL : blob_memdup(msg);
	ifc->up = !down && (!tb[DYN_UP] || blobmsg_get_bool(tb[DYN_UP]));
	if (ifc->up)
		apply_dynamic(ifc, false);
	notify(ifc);
	reassign_all();
	return 0;
}

static const struct ubus_method iface_methods[] = {
	UBUS_METHOD_NOARG("dump", handle_dump),
	UBUS_METHOD("update", handle_update, dyn_policy),
	UBUS_METHOD("down", handle_update, dyn_policy),
};

static struct ubus_object_type iface_type = UBUS_OBJECT_TYPE("netifd_iface", iface_methods);

static struct ubus_object iface_obj = {
	.name = "network.interface",
	.type = &iface_type,
	.methods = iface_methods,
	.n_methods = ARRAY_SIZE(iface_methods),
};

static int load_config(const char *path)
{
	static const struct blobmsg_policy top[2] = {
		{ .name = "ula_prefix", .type = BLOBMSG_TYPE_STRING },
		{ .name = "interfaces", .type = BLOBMSG_TYPE_TABLE },
	};
	static const struct blobmsg_policy ipol[5] = {
		{ .name = "device", .type = BLOBMSG_TYPE_STRING },
		{ .name = "proto", .type = BLOBMSG_TYPE_STRING },
		{ .name = "ip6assign", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "ip6hint", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "auto", .type = BLOBMSG_TYPE_BOOL },
	};
	static struct blob_buf cb;
	struct blob_attr *tb[2], *cur;
	size_t rem;

	blob_buf_init(&cb, 0);
	if (!blobmsg_add_json_from_file(&cb, path)) {
		logmsg("can't parse %s", path);
		return -1;
	}
	blobmsg_parse(top, 2, tb, blob_data(cb.head), blob_len(cb.head));
	if (tb[0])
		have_ula = parse_prefix(blobmsg_get_string(tb[0]), &ula);
	if (!tb[1])
		return 0;

	blobmsg_for_each_attr(cur, tb[1], rem) {
		struct blob_attr *it[5];
		struct iface *ifc = calloc(1, sizeof(*ifc));

		blobmsg_parse(ipol, 5, it, blobmsg_data(cur), blobmsg_data_len(cur));
		ifc->name = strdup(blobmsg_name(cur));
		ifc->device = strdup(it[0] ? blobmsg_get_string(it[0]) : ifc->name);
		ifc->proto = strdup(it[1] ? blobmsg_get_string(it[1]) : "static");
		ifc->ip6assign = it[2] ? blobmsg_get_u32(it[2]) : 0;
		ifc->ip6hint = it[3] ? blobmsg_get_u32(it[3]) : 0;
		ifc->is_static = !strcmp(ifc->proto, "static") || !strcmp(ifc->proto, "none");
		ifc->up = ifc->is_static;
		ifc->config = blob_memdup(cur);
		list_add_tail(&ifc->list, &ifaces);
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *config = NULL, *socket = NULL;
	struct iface *ifc;
	int opt;

	while ((opt = getopt(argc, argv, "c:s:")) != -1) {
		switch (opt) {
		case 'c':
			config = optarg;
			break;
		case 's':
			socket = optarg;
			break;
		default:
			fprintf(stderr, "usage: %s -c <config.json> [-s <ubus socket>]\n", argv[0]);
			return 1;
		}
	}
	if (!config || load_config(config))
		return 1;

	list_for_each_entry(ifc, &ifaces, list)
		if (ifc->is_static)
			apply_static(ifc);

	uloop_init();
	ctx = ubus_connect(socket);
	if (!ctx) {
		logmsg("can't connect to ubus");
		return 1;
	}
	ubus_add_uloop(ctx);
	if (ubus_add_object(ctx, &iface_obj)) {
		logmsg("can't register network.interface");
		return 1;
	}
	reassign_all();
	logmsg("ready");
	uloop_run();
	return 0;
}
