// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include "socket_helpers.h"
#include <bpf/bpf_helpers.h>

SEC("sockops")
int config_tcp(struct bpf_sock_ops *skops)
{
	int op;
	int rv = 0;
	int clamp = 100;
	int bufsize = 1500000;
	int rwnd_init = 40;
	int iw = 40;

	// Compute TCP parameters based on connection properties

	// Apply TCP parameters
	op = (int) skops->op;
	switch (op) {
	case BPF_SOCK_OPS_TIMEOUT_INIT:
		break;
	case BPF_SOCK_OPS_RWND_INIT:
		// Set the initial advertized window
		rv = rwnd_init;
		break;
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		// Set the send and receive buffers
		rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF,
				    &bufsize, sizeof(bufsize));
		rv += bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
				     &bufsize, sizeof(bufsize));
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		// Set the initial congestion window
		rv = bpf_setsockopt(skops, IPPROTO_TCP,
				    TCP_BPF_IW, &iw, sizeof(iw));
		// Clamp the congestion window
		rv = bpf_setsockopt(skops, IPPROTO_TCP,
				TCP_BPF_SNDCWND_CLAMP,
				&clamp, sizeof(clamp));
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		/* Clamp the congestion window, and set the send
		 * and receive buffers
		 */
		rv = bpf_setsockopt(skops, IPPROTO_TCP,
				    TCP_BPF_SNDCWND_CLAMP,
				    &clamp, sizeof(clamp));
		rv += bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF,
				     &bufsize, sizeof(bufsize));
		rv += bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
				     &bufsize, sizeof(bufsize));
		break;
	case BPF_SOCK_OPS_NEEDS_ECN:
		break;
	case BPF_SOCK_OPS_BASE_RTT:
		break;
	case BPF_SOCK_OPS_RTO_CB:
		break;
	case BPF_SOCK_OPS_RETRANS_CB:
		break;
	case BPF_SOCK_OPS_STATE_CB:
		break;
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		break;
	case BPF_SOCK_OPS_RTT_CB:
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
