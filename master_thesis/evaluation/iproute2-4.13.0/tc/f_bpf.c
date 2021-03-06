/*
 * f_bpf.c	BPF-based Classifier
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Daniel Borkmann <daniel@iogearbox.net>
 */

#include <stdio.h>
#include <stdlib.h>

#include <linux/bpf.h>

#include "utils.h"

#include "tc_util.h"
#include "bpf_util.h"

static const enum bpf_prog_type bpf_type = BPF_PROG_TYPE_SCHED_CLS;

static void explain(void)
{
	fprintf(stderr, "Usage: ... bpf ...\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "BPF use case:\n");
	fprintf(stderr, " bytecode BPF_BYTECODE\n");
	fprintf(stderr, " bytecode-file FILE\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "eBPF use case:\n");
	fprintf(stderr, " object-file FILE [ section CLS_NAME ] [ export UDS_FILE ]");
	fprintf(stderr, " [ verbose ] [ direct-action ] [ skip_hw | skip_sw ]\n");
	fprintf(stderr, " object-pinned FILE [ direct-action ] [ skip_hw | skip_sw ]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Common remaining options:\n");
	fprintf(stderr, " [ action ACTION_SPEC ]\n");
	fprintf(stderr, " [ classid CLASSID ]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where BPF_BYTECODE := \'s,c t f k,c t f k,c t f k,...\'\n");
	fprintf(stderr, "c,t,f,k and s are decimals; s denotes number of 4-tuples\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where FILE points to a file containing the BPF_BYTECODE string,\n");
	fprintf(stderr, "an ELF file containing eBPF map definitions and bytecode, or a\n");
	fprintf(stderr, "pinned eBPF program.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where CLS_NAME refers to the section name containing the\n");
	fprintf(stderr, "classifier (default \'%s\').\n", bpf_prog_to_default_section(bpf_type));
	fprintf(stderr, "\n");
	fprintf(stderr, "Where UDS_FILE points to a unix domain socket file in order\n");
	fprintf(stderr, "to hand off control of all created eBPF maps to an agent.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "ACTION_SPEC := ... look at individual actions\n");
	fprintf(stderr, "NOTE: CLASSID is parsed as hexadecimal input.\n");
}

static void bpf_cbpf_cb(void *nl, const struct sock_filter *ops, int ops_len)
{
	addattr16(nl, MAX_MSG, TCA_BPF_OPS_LEN, ops_len);
	addattr_l(nl, MAX_MSG, TCA_BPF_OPS, ops,
		  ops_len * sizeof(struct sock_filter));
}

static void bpf_ebpf_cb(void *nl, int fd, const char *annotation)
{
	addattr32(nl, MAX_MSG, TCA_BPF_FD, fd);
	addattrstrz(nl, MAX_MSG, TCA_BPF_NAME, annotation);
}

static const struct bpf_cfg_ops bpf_cb_ops = {
	.cbpf_cb = bpf_cbpf_cb,
	.ebpf_cb = bpf_ebpf_cb,
};

static int bpf_parse_opt(struct filter_util *qu, char *handle,
			 int argc, char **argv, struct nlmsghdr *n)
{
	const char *bpf_obj = NULL, *bpf_uds_name = NULL;
	struct tcmsg *t = NLMSG_DATA(n);
	unsigned int bpf_gen_flags = 0;
	unsigned int bpf_flags = 0;
	struct bpf_cfg_in cfg = {};
	bool seen_run = false;
	struct rtattr *tail;
	int ret = 0;

	if (handle) {
		if (get_u32(&t->tcm_handle, handle, 0)) {
			fprintf(stderr, "Illegal \"handle\"\n");
			return -1;
		}
	}

	if (argc == 0)
		return 0;

	tail = (struct rtattr *)(((void *)n) + NLMSG_ALIGN(n->nlmsg_len));
	addattr_l(n, MAX_MSG, TCA_OPTIONS, NULL, 0);

	while (argc > 0) {
		if (matches(*argv, "run") == 0) {
			NEXT_ARG();
opt_bpf:
			seen_run = true;
			cfg.argc = argc;
			cfg.argv = argv;

			if (bpf_parse_common(bpf_type, &cfg, &bpf_cb_ops, n))
				return -1;

			argc = cfg.argc;
			argv = cfg.argv;

			bpf_obj = cfg.object;
			bpf_uds_name = cfg.uds;
		} else if (matches(*argv, "classid") == 0 ||
			   matches(*argv, "flowid") == 0) {
			unsigned int handle;

			NEXT_ARG();
			if (get_tc_classid(&handle, *argv)) {
				fprintf(stderr, "Illegal \"classid\"\n");
				return -1;
			}
			addattr32(n, MAX_MSG, TCA_BPF_CLASSID, handle);
		} else if (matches(*argv, "direct-action") == 0 ||
			   matches(*argv, "da") == 0) {
			bpf_flags |= TCA_BPF_FLAG_ACT_DIRECT;
		} else if (matches(*argv, "skip_hw") == 0) {
			bpf_gen_flags |= TCA_CLS_FLAGS_SKIP_HW;
		} else if (matches(*argv, "skip_sw") == 0) {
			bpf_gen_flags |= TCA_CLS_FLAGS_SKIP_SW;
		} else if (matches(*argv, "action") == 0) {
			NEXT_ARG();
			if (parse_action(&argc, &argv, TCA_BPF_ACT, n)) {
				fprintf(stderr, "Illegal \"action\"\n");
				return -1;
			}
			continue;
		} else if (matches(*argv, "police") == 0) {
			NEXT_ARG();
			if (parse_police(&argc, &argv, TCA_BPF_POLICE, n)) {
				fprintf(stderr, "Illegal \"police\"\n");
				return -1;
			}
			continue;
		} else if (matches(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			if (!seen_run)
				goto opt_bpf;

			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}

		NEXT_ARG_FWD();
	}

	if (bpf_gen_flags)
		addattr32(n, MAX_MSG, TCA_BPF_FLAGS_GEN, bpf_gen_flags);
	if (bpf_flags)
		addattr32(n, MAX_MSG, TCA_BPF_FLAGS, bpf_flags);

	tail->rta_len = (((void *)n) + n->nlmsg_len) - (void *)tail;

	if (bpf_uds_name)
		ret = bpf_send_map_fds(bpf_uds_name, bpf_obj);

	return ret;
}

static int bpf_print_opt(struct filter_util *qu, FILE *f,
			 struct rtattr *opt, __u32 handle)
{
	struct rtattr *tb[TCA_BPF_MAX + 1];
	int dump_ok = 0;

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_BPF_MAX, opt);

	if (handle)
		fprintf(f, "handle 0x%x ", handle);

	if (tb[TCA_BPF_CLASSID]) {
		SPRINT_BUF(b1);
		fprintf(f, "flowid %s ",
			sprint_tc_classid(rta_getattr_u32(tb[TCA_BPF_CLASSID]), b1));
	}

	if (tb[TCA_BPF_NAME])
		fprintf(f, "%s ", rta_getattr_str(tb[TCA_BPF_NAME]));

	if (tb[TCA_BPF_FLAGS]) {
		unsigned int flags = rta_getattr_u32(tb[TCA_BPF_FLAGS]);

		if (flags & TCA_BPF_FLAG_ACT_DIRECT)
			fprintf(f, "direct-action ");
	}

	if (tb[TCA_BPF_FLAGS_GEN]) {
		unsigned int flags =
			rta_getattr_u32(tb[TCA_BPF_FLAGS_GEN]);

		if (flags & TCA_CLS_FLAGS_SKIP_HW)
			fprintf(f, "skip_hw ");
		if (flags & TCA_CLS_FLAGS_SKIP_SW)
			fprintf(f, "skip_sw ");

		if (flags & TCA_CLS_FLAGS_IN_HW)
			fprintf(f, "in_hw ");
		else if (flags & TCA_CLS_FLAGS_NOT_IN_HW)
			fprintf(f, "not_in_hw ");
	}

	if (tb[TCA_BPF_OPS] && tb[TCA_BPF_OPS_LEN])
		bpf_print_ops(f, tb[TCA_BPF_OPS],
			      rta_getattr_u16(tb[TCA_BPF_OPS_LEN]));

	if (tb[TCA_BPF_ID])
		dump_ok = bpf_dump_prog_info(f, rta_getattr_u32(tb[TCA_BPF_ID]));
	if (!dump_ok && tb[TCA_BPF_TAG]) {
		SPRINT_BUF(b);

		fprintf(f, "tag %s ",
			hexstring_n2a(RTA_DATA(tb[TCA_BPF_TAG]),
				      RTA_PAYLOAD(tb[TCA_BPF_TAG]),
				      b, sizeof(b)));
	}

	if (tb[TCA_BPF_POLICE]) {
		fprintf(f, "\n");
		tc_print_police(f, tb[TCA_BPF_POLICE]);
	}

	if (tb[TCA_BPF_ACT])
		tc_print_action(f, tb[TCA_BPF_ACT]);

	return 0;
}

struct filter_util bpf_filter_util = {
	.id		= "bpf",
	.parse_fopt	= bpf_parse_opt,
	.print_fopt	= bpf_print_opt,
};
