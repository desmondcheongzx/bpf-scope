/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include "socket_helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "tcp.h"

SEC("fentry/func")
int BPF_PROG(trace_on_entry, struct xdp_buff *xdp)
{
	bpf_printk("We tracin'\n");
	return 0;
}

char _license[] SEC("license") = "GPL";
