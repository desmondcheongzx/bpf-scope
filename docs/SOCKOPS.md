## Notes on BPF socket operations

A reference based on `include/uapi/linux/bpf.h`.

### BPF_SOCK_OPS_VOID

### BPF_SOCK_OPS_TIMEOUT_INIT

Should return SYN-RTO value to use or -1 if default value should be used.

### BPF_SOCK_OPS_RWND_INIT

Should return initial advertized window (in packets) or -1 if default value should be used.
					 
### BPF_SOCK_OPS_TCP_CONNECT_CB

Calls BPF program right before an active connection is initialized.
					 
### BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB

Calls BPF program when an active connection is established.
						 
### BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB

Calls BPF program when a passive connection is established.
						 
### BPF_SOCK_OPS_NEEDS_ECN

If connection's congestion control needs ECN.
					 
### BPF_SOCK_OPS_BASE_RTT

Get base RTT. The correct value is based on the path and may be dependent on the congestion control algorithm. In general it indicates a congestion threshold. RTTs above this indicate congestion.

### BPF_SOCK_OPS_RTO_CB

Called when an RTO has triggered.

Arg1: value of icsk_retransmits

Arg2: value of icsk_rto

Arg3: whether RTO has expired
					 
### BPF_SOCK_OPS_RETRANS_CB

Called when skb is retransmitted.

Arg1: sequence number of 1st byte

Arg2: # segments

Arg3: return value of tcp_transmit_skb (0 => success)
					 
### BPF_SOCK_OPS_STATE_CB

Called when TCP changes state.

Arg1: old_state

Arg2: new_state
					 
### BPF_SOCK_OPS_TCP_LISTEN_CB

Called on listen(2), right after socket transition to LISTEN state.
					 
### BPF_SOCK_OPS_RTT_CB

Called on every RTT.
					 
### BPF_SOCK_OPS_PARSE_HDR_OPT_CB

Parse the header option. It will be called to handle the packets received at an already established connection.

sock_ops->skb_data: Referring to the received skb. It covers the TCP header only.

bpf_load_hdr_opt() can also be used to search for a particular option.
					 
### BPF_SOCK_OPS_HDR_OPT_LEN_CB

Reserve space for writing the header option later in BPF_SOCK_OPS_WRITE_HDR_OPT_CB.

Arg1: bool want_cookie. (in writing SYNACK only)

sock_ops->skb_data: Not available because no header has been written yet.

sock_ops->skb_tcp_flags: The tcp_flags of the outgoing skb. (e.g. SYN, ACK, FIN).

bpf_reserve_hdr_opt() should be used to reserve space.
					 
### BPF_SOCK_OPS_WRITE_HDR_OPT_CB

Write the header options

Arg1: bool want_cookie. (in writing SYNACK only)

sock_ops->skb_data: Referring to the outgoing skb. It covers the TCP header that has already been written by the kernel and the earlier bpf-progs.

sock_ops->skb_tcp_flags: The tcp_flags of the outgoing skb. (e.g. SYN, ACK, FIN).

bpf_store_hdr_opt() should be used to write the option.

bpf_load_hdr_opt() can also be used to search for a particular option that has already been written by the kernel or the earlier bpf-progs.
