// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "socket_helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static void parse_ipv4(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if ((void *)(iph + 1) > data_end)
		return;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return 0;
	parse_ipv4(data, nh_off, data_end);
        return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
