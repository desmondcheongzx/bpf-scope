#!/bin/bash
set -x
set -e

# Mount bpf filesystem
sudo mount -t bpf bpf /sys/fs/bpf/

# Load the bpf sockops program
sudo bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops name $1
