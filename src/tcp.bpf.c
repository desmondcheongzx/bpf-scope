// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

SEC("sockops")
int tcp_config(struct bpf_sock_ops *skops)
{
	__u32 family, op;

	family = skops->family;
	op = skops->op;

	bpf_printk("<<< op %d, port = %d --> %d\n", op, skops->local_port, skops->remote_port);
	return 0;
}
