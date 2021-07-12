#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define MAX_UDP_SIZE 1480
#define MAX_TCP_SIZE 4096
#define ETH_P_IP 0x0800		/* Internet Protocol packet	*/

static __always_inline __u16 csum_fold_helper(__u32 csum) {
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline void ipv4_csum(void *data_start, int data_size,
				__u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
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
	csum_buffer += (__u16)iph->tos;
	csum_buffer += (__u16)iph->ttl;
	csum_buffer += (__u16)iph->check;
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
	csum_buffer += (__u16)iph->tos;
	csum_buffer += (__u16)iph->ttl;
	csum_buffer += (__u16)iph->check;

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

static __u16 calc_csum(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	__u16 checksum = 0;

	if ((void *)eth + sizeof(*eth) > data_end)
		goto out;
	ip = data + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end)
		goto out;
	/* calculate initial checksum */
	switch (ip->protocol) {
	case IPPROTO_TCP:
		tcp = data + sizeof(*eth) + sizeof(*ip);
		if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
			return XDP_DROP;
		checksum = calc_tcp_csum(ip, tcp, data_end);
		break;
	case IPPROTO_UDP:
		udp = data + sizeof(*eth) + sizeof(*ip);
		if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
			return XDP_DROP;
		checksum = calc_udp_csum(ip, udp, data_end);
		break;
	default:
		break;
	}

out:
	return checksum;
}

struct id_t {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8 protocol;
};

BPF_HASH(counter, struct id_t, u32, 1024);

static int udp_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u32 csum = 0;

	if ((void *)eth + sizeof(*eth) > data_end)
		return XDP_PASS;
	ip = data + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end)
		return XDP_PASS;
	if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (void *)ip + sizeof(*ip);
		if ((void *)udp + sizeof(*udp) <= data_end) {
			bpf_trace_printk("Do some XDP thing\n");
		}
	}
	/* touch tos field */
	ip->tos = 1;
	ip->check = 0;
	ipv4_csum(ip, sizeof(*ip), &csum);
	ip->check = csum;

	return XDP_PASS;
}

int bpf_scope_xdp(struct xdp_md *ctx)
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

	/* construct key */
	if ((void *)eth + sizeof(*eth) > data_end)
		goto out;
	ip = data + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end)
		goto out;
	key.saddr = ip->saddr;
	key.daddr = ip->daddr;
	key.protocol = ip->protocol;
	switch (ip->protocol) {
	case IPPROTO_TCP:
		tcp = data + sizeof(*eth) + sizeof(*ip);
		if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
			goto out;
		key.sport = htons(tcp->source);
		key.dport = htons(tcp->dest);
		break;
	case IPPROTO_UDP:
		udp = data + sizeof(*eth) + sizeof(*ip);
		if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
			goto out;
		key.sport = htons(udp->source);
		key.dport = htons(udp->dest);
		break;
	default:
		return udp_prog(ctx);
	}
	starting_checksum = calc_csum(ctx);

	/* call XDP program */
	ret = udp_prog(ctx);

	ending_checksum = calc_csum(ctx);

	bpf_trace_printk("starting: %u, ending: %u\n",
			starting_checksum, ending_checksum);
	if (starting_checksum != ending_checksum) {
		bpf_trace_printk("packet changed\n");
		val = counter.lookup_or_try_init(&key, &zero);
		if (val) {
			(*val)++;
			bpf_trace_printk("val: %lu\n", *val);
		}
	}

	return ret;

out:
	return XDP_PASS;
}
