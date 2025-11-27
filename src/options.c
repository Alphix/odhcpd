/*
 * SPDX-FileCopyrightText: 2025 David Härdeman <david@hardeman.nu>
 *
 * SPDX-License-Identifier: GPL2.0-only
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "odhcpd.h"
#include "options.h"
#include "dhcpv4.h"

struct foobar {
	struct vlist_node node;
	uint16_t code;
	uint16_t len;
	uint8_t data[];
};

static inline size_t options_count_commas(const char *str, size_t len) {
	int count = 0;
	const char *end = str + len;

	if (!str || !len)
		return 0;

	for (const char *p = str; (p = memchr(p, ',', end - p)); p++)
		count++;

	return count;
}

static inline struct foobar *options_alloc_opt(size_t data_len)
{
	struct foobar *opt = malloc(sizeof(*opt) + data_len);

	if (!opt)
		return NULL;

	opt->len = data_len;
	return opt;
}

static struct foobar *options_parse_ip(const char *data, size_t data_len, bool v6)
{
	size_t addrs_cnt = options_count_commas(data, data_len) + 1;
	size_t addrs_len = addrs_cnt * (v6 ? sizeof(struct in6_addr) : sizeof(struct in_addr));
	struct foobar *opt = options_alloc_opt(addrs_len);
	struct in_addr *addrs4;
	struct in6_addr *addrs6;
	int i = 0;
	const char *end = data + data_len;

	fprintf(stderr, "HERE\n");

	if (!opt)
		return NULL;

	fprintf(stderr, "addrs_cnt is %zu\n", addrs_cnt);

	addrs4 = (struct in_addr *)opt->data;
	addrs6 = (struct in6_addr *)opt->data;

	for (const char *start = data; start < end;) {
		const char *comma = memchr(start, ',', end - start);
		const char *addr_end = comma ? comma : end;
		size_t addr_len = addr_end - start;
		char buf[INET6_ADDRSTRLEN];

		if (addr_len >= INET6_ADDRSTRLEN)
			goto err;

		fprintf(stderr, "start is %s\n", start);
		fprintf(stderr, "addr_len is %zu\n", addr_len);
		memcpy(buf, start, addr_len);
		buf[addr_len] = '\0';

		if (v6 && inet_pton(AF_INET6, buf, &addrs6[i++]) != 1)
			goto err;

		if (!v6 && inet_pton(AF_INET, buf, &addrs4[i++]) != 1)
			goto err;

		if (!comma)
			break;
		start = comma + 1;
	}

	return opt;

err:
	free(opt);
	return NULL;
}

static struct foobar *options_parse_hex(const char *data, size_t data_len)
{
	struct foobar *opt;
	size_t opt_len = data_len / 2;
	ssize_t r;

	if (!data || !data_len || data_len % 2)
		return NULL;

	opt = options_alloc_opt(opt_len);
	if (!opt)
		return NULL;

	opt->len = opt_len;
	r = odhcpd_unhexlify(opt->data, opt_len, data);
	if (r < 0 || (size_t)r != opt_len) {
		free(opt);
		return NULL;
	}

	return opt;
}

static inline size_t options_data_len(const char *opt, size_t opt_len, const char *data)
{
	return opt_len - (size_t)(data - opt);
}

static inline bool strprefix(char **str, const char *prefix)
{
	size_t plen = strlen(prefix);

	if (strncmp(*str, prefix, plen))
		return false;

	*str += plen;
	return true;
}

//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpe/26884b0d-8866-4aa5-8281-4b672387b7e0

/* syntax: <opt-code>,<option,...,><encoding>:<data> */
static struct foobar *options_add_dhcpv4(const char *opt_str, size_t opt_str_len, bool *forced)
{
	char *sep;
	unsigned long code;
	_o_unused bool ms_long = false;
	size_t data_len = 0;
	struct foobar *opt = NULL;

	*forced = false;
	code = strtoul(opt_str, &sep, 0);
	fprintf(stderr, "code is %u\n", (unsigned)code);
	if (code <= DHCPV4_OPT_PAD /* 0 */ || code >= DHCPV4_OPT_END /* 255 */ || !sep)
		return false;

	while (*sep == ',') {
		sep++;

		fprintf(stderr, "In loop, sep %s\n", sep);

		if (strprefix(&sep, "force")) {
			*forced = true;
			continue;
		} else if (strprefix(&sep, "ms-long")) {
			ms_long = true;
			continue;
		} else if (strprefix(&sep, "ipv4:")) {
			fprintf(stderr, "In subloop, str %s\n", sep);
			data_len = options_data_len(opt_str, opt_str_len, sep);
			fprintf(stderr, "In subloop, data_len %zu\n", data_len);
			opt = options_parse_ip(sep, data_len, false);
			break;
		} else if (strprefix(&sep, "ipv6:")) {
			data_len = options_data_len(opt_str, data_len, sep);
			opt = options_parse_ip(sep, data_len, true);
			break;
		} else if (strprefix(&sep, "hex:")) {
			data_len = options_data_len(opt_str, data_len, sep);
			opt = options_parse_hex(sep, data_len);
			break;
		} else if (strprefix(&sep, "str:")) {
			data_len = options_data_len(opt_str, data_len, sep);
			opt = options_alloc_opt(data_len);
			if (opt)
				memcpy(opt->data, sep, data_len);
			break;
		} else if (!strcmp(sep, "none")) {
			opt = options_alloc_opt(0);
			break;
		}
		break;
	}

	if (opt)
		opt->code = code;

	return opt;
}

bool options_add_dhcpv4_iface(const char *opt_str, size_t opt_str_len, struct interface *iface)
{
	bool forced;
	struct foobar *opt;
	struct vlist_tree *opt_list;

	opt = options_add_dhcpv4(opt_str, opt_str_len, &forced);
	if (!opt)
		return false;

	if (forced)
		opt_list = &iface->dhcpv4_options;
	else
		opt_list = &iface->dhcpv4_forced_options;

	vlist_add(opt_list, &opt->node, opt);

	return true;
}

static int options_vlist_cmp(const void *k1, const void *k2, void *ptr)
{
	const struct foobar *opt1 = k1, *opt2 = k2;

	if (opt1->code == opt2->code)
		return 0;

	return opt1->code < opt2->code ? -1 : 1;
}

static void options_vlist_update(_o_unused struct vlist_tree *tree,
				 struct vlist_node *node_new,
				 struct vlist_node *node_old)
{
	struct foobar *opt_new = container_of(node_new, struct foobar, node);
	struct foobar *opt_old = container_of(node_old, struct foobar, node);

	if (node_old && node_new)
		/* FIXME */
		debug("In %s: opt_new %u opt_old %u", __func__, opt_new->code, opt_old->code);
	else if (node_old)
		free(opt_old);
}

void options_init_iface(struct interface *iface)
{
	vlist_init(&iface->dhcpv4_options, options_vlist_cmp, options_vlist_update);
	vlist_init(&iface->dhcpv4_forced_options, options_vlist_cmp, options_vlist_update);
}

void options_clean_iface(struct interface *iface)
{
	vlist_flush(&iface->dhcpv4_options);
	vlist_flush(&iface->dhcpv4_forced_options);
}

/*
int main(int argc, char **argv)
{
	struct dhcpv4_option *opt;
	char *str = "52,ipv4:192.168.99.1,1.2.3.4,5.6.7.1111";
	struct in_addr *addrs;

	opt = options_add_dhcpv4(str, strlen(str));

	fprintf(stderr, "opt is 0x%p\n", opt);
	if (!opt)
		return 0;

	fprintf(stderr, "opt->code is %zu\n", opt->code);
	fprintf(stderr, "opt->len is %zu\n", opt->len);

	addrs = (struct in_addr *)opt->data;
	for (unsigned i = 0; i < opt->len / sizeof(struct in_addr); i++) {
		struct in_addr addr = addrs[i];
		char buf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &addr, buf, sizeof(buf));
		fprintf(stderr, "IPv4: %s\n", buf);
	}

	return 0;
}
*/
