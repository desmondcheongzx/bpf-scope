// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

int main(int argc, char **argv)
{
	int map_fd;
	union bpf_attr attr = {
		.map_type    = BPF_MAP_TYPE_HASH,
		.key_size    = sizeof(int),
		.value_size  = sizeof(int),
		.max_entries = 256
	};

	map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (map_fd < 0) {
		printf("failed to create map '%s'\n",
			strerror(map_fd));
		return 1;
	}
	return 0;
}
