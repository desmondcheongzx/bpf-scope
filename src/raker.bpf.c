// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "socket_helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_UDP_SIZE 1480
#define MAX_TCP_SIZE 8192
#define ETH_P_IP 0x0800		/* Internet Protocol packet	*/

static __always_inline __u16 csum_fold_helper(__u32 csum) {
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u16 calc_udp_csum(struct iphdr *iph,
					   struct udphdr *udph, void *data_end)
{
	__u32 csum_buffer = 0;
	__u16 *buf = (void *)udph;

	// Compute pseudo-header checksum;
	csum_buffer += (__u16)iph->saddr;
	csum_buffer += (__u16)(iph->saddr >> 16);
	csum_buffer += (__u16)iph->daddr;
	csum_buffer += (__u16)(iph->daddr >> 16);
	csum_buffer += (__u16)iph->protocol >> 8;
	csum_buffer += udph->len;

	// Compute checksum on udp header + payload
	for (int i = 0; i < MAX_UDP_SIZE; i += 2) {
		if ((void *)(buf + 1) > data_end)
			break;
		csum_buffer += *buf;
		buf++;
	}

	if ((void *)buf + 1 <= data_end) {
		// In case payload is not 2 bytes aligned
		csum_buffer += *(__u8 *)buf;
	}

	return csum_fold_helper(csum_buffer);
}

static __always_inline __u16 calc_tcp_csum(struct iphdr *iph,
					   struct tcphdr *tcph, void *data_end)
{
	__u16 ip_header_length = 0;
	__u32 csum_buffer = 0;
	__u16 *buf = (void *)tcph;
	__u16 payload_length;

	// Compute pseudo-header checksum;
	csum_buffer += (__u16)iph->saddr;
	csum_buffer += (__u16)(iph->saddr >> 16);
	csum_buffer += (__u16)iph->daddr;
	csum_buffer += (__u16)(iph->daddr >> 16);
	csum_buffer += (__u16)iph->protocol >> 8;

	ip_header_length = iph->ihl << 2;
	payload_length = iph->tot_len - ip_header_length;
	csum_buffer += payload_length;

	// Compute checksum on udp header + payload
	for (int i = 0; i < MAX_TCP_SIZE; i += 2) {
		if ((void *)(buf + 1) > data_end)
			break;
		csum_buffer += *buf;
		buf++;
	}

	if ((void *)buf + 1 <= data_end) {
		// In case payload is not 2 bytes aligned
		csum_buffer += *(__u8 *)buf;
	}

	return csum_fold_helper(csum_buffer);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 checksum;
	struct tcphdr *tcp;
	struct udphdr *udp;

	bpf_printk("XDP\n");
	if ((void *)eth + sizeof(*eth) > data_end)
		goto DROP;

	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end)
		goto DROP;
	bpf_printk("Proto: %d\n", ip->protocol);
	switch (ip->protocol) {
	case IPPROTO_TCP:
		tcp = data + sizeof(*eth) + sizeof(*ip);
		if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
			return XDP_DROP;
		checksum = calc_tcp_csum(ip, tcp, data_end);
		bpf_printk("Calculated TCP checksum is %x\n", checksum);
		break;
	case IPPROTO_UDP:
		udp = data + sizeof(*eth) + sizeof(*ip);
		if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
			return XDP_DROP;
		checksum = calc_udp_csum(ip, udp, data_end);
		bpf_printk("Calculated UDP checksum is %x\n", checksum);
		break;
	default:
		goto DROP;
	}

DROP:
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
