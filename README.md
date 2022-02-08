# BPF-scope (name to be determined)

## Repository overview

```
.
├── libbpf => submodule at https://github.com/libbpf/libbpf
├── LICENSE
├── README.md
├── src
│   ├── <program>.bpf.c
│   ├── <program>.h (optional)
│   ├── socket_helpers.h
│   ├── Makefile
│   └── vmlinux.h
└── tools
    └── bpftool
```

Notes:

`socket_helpers.h` contains some missing `#define` macros in `vmlinux.h`. Currently this contains the macros from `include/uapi/asm-generic/socket.h` in the kernel tree such as for `SOL_SOCKET`, `SO_SNDBUF` etc.

`vmlinux.h` can be generated using [this script](https://github.com/libbpf/libbpf-bootstrap/blob/master/tools/gen_vmlinux_h.sh) from [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap):

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

`bpftool` should be available from an appropriate package in your Linux distribution. E.g. [Arch](https://archlinux.org/packages/community/x86_64/bpf/)

## Requirements

To use BPF CO-RE and kernel BTF support, the Linux kernel needs to be built with `CONFIG_DEBUG_INFO_BTF=y`. Refer to [libbpf](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere) to check if your Linux distro already does this.

## Usage

To recompile the TCP-BPF program, run `make tcp` inside the `src/` directory. A `tcp` binary should be generated.

To attach the TCP-BPF program, run `tools/load.sh config_tcp` (this is the name of the BPF program in `src/tcp.bpf.c`). To detach it, run `tools/unload.sh config_tcp`. The bpf program's debugging output is sent to `/sys/kernel/debug/tracing/trace_pipe`.

## BPF programming

### TCP-BPF

Notes on when socket operations trigger BPF programs can be found under `include/uapi/linux/bpf.h` in the kernel tree, or [here](docs/SOCKOPS.md).

## Benchmarking
### Install wrk2 benchmarker

```
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev git zlib1g-dev
git clone https://github.com/giltene/wrk2.git
cd wrk2
make
# move the executable to somewhere in your PATH
sudo cp wrk /usr/local/bin
```

### Install Apache

```
sudo apt install apache2
```

### Install Docker

If needed.

```
sudo apt update
sudo apt install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io
```

Verify that docker is installed:

```
docker run hello-world
```
