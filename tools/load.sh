#!/bin/bash
set -x
set -e

# Mount bpf filesystem
sudo mount -t bpf bpf /sys/fs/bpf/

# Load the bpf sockops program
sudo bpftool prog load $1.o "/sys/fs/bpf/bpf_sockop"
sudo bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockop"
