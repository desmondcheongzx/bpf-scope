/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include "socket_helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcp.h"

struct id_t {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8 protocol;
};

SEC("xdp")
int myfunc(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	__u16 starting_checksum;
	__u16 ending_checksum;
	__u32 csum = 0;
	int ret;
	struct id_t key = {};
	u32 zero = 0, *val;

	if ((void *)eth + sizeof(*eth) > data_end)
		goto out;
	ip = data + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end)
		goto out;
	key.saddr = ip->saddr;
	key.daddr = ip->daddr;
	key.protocol = ip->protocol;

out:
	bpf_printk("Returning XDP_PASS\n");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
