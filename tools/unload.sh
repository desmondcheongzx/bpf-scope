#!/bin/bash
set -x

# UnLoad the bpf sockops program
sudo bpftool cgroup detach "/sys/fs/cgroup/unified/" sock_ops name $1
