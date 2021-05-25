#!/bin/bash
set -x

# UnLoad the bpf sockops program
sudo bpftool cgroup detach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockop"
sudo rm "/sys/fs/bpf/bpf_sockop"
