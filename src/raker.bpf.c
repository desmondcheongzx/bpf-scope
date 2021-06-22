// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "socket_helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline __u16 csum_fold_helper(__u32 csum) {
	int i;
#pragma unroll
	for (i = 0; i < 2; i ++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

static __always_inline void ipv4_csum(void *data_start, int data_size,
				__u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

static void parse_ipv4(void *data, u64 nh_off, void *data_end)
{
	__u32 csum = 0;
	__u32 csum2 = 0;
	struct iphdr *iph = data + nh_off;

	if ((void *)(iph + 1) > data_end)
		return;
	int ver = iph->version;
	int check = iph->check;
	if (ver == 4) {
		iph->check = 0;
		ipv4_csum(iph, sizeof(struct iphdr), &csum2);
		ipv4_csum(iph, sizeof(struct iphdr), &csum);
		check = csum;
		iph->check = csum;
	}
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
