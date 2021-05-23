// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("sockops")
int config_tcp(struct bpf_sock_ops *skops)
{
	int op;

	op = (int) skops->op;
	bpf_printk("BPF command: %d\n", op);
	return 0;
}
