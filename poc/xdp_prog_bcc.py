from bcc import BPF
from bcc.utils import printb
import socket
import struct

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def int2proto(proto):
    if proto == 17:
        return "UDP"
    if proto == 6:
        return "TCP"
    return "-"

device = "lo"
b = BPF(src_file="xdp_prog.c")
fn = b.load_func("bpf_scope_xdp", BPF.XDP)
b.attach_xdp(device, fn, 0)

try:
    b.trace_print()
except KeyboardInterrupt:
    dist = b["counter"]
    for k, v in dist.items():
        print(f"FROM {int2ip(k.saddr)}:{k.sport} TO {int2ip(k.daddr)}:{k.dport} via {int2proto(k.protocol)},  COUNT: {v.value}")

b.remove_xdp(device, 0)
