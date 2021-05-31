// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcp.h"
#include "tcp.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static struct bpf_object* get_bpf_object(char* path)
{
	struct bpf_object* obj = bpf_object__open(path);
	if (!obj) {
		printf("Failed to load bpf_object from %s\n", path);
		return NULL;
	}
	return obj;
}

int get_map_fd(struct bpf_object* obj, const char* name)
{
	struct bpf_map* map = bpf_object__find_map_by_name(obj, name);
	if (map == NULL) {
		printf("Failed to find map %s\n", name);
		return -1;
	}
	return bpf_map__fd(map);
}

int main(int argc, char **argv)
{
	struct tcp_bpf *skel;
	struct config value;
	int map_fd;
	int err;

	value.nbits = 10;
	value.addr = 2130706433; // 127.0.0.1
	value.rwnd_init = 1;
	value.iw = 2;
	value.bufsize = 5;
	value.clamp = 10;
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open BPF application */
	skel = tcp_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->bss->table_size = 0;
	char* bpf_file = ".output/tcp.bpf.o";
	struct bpf_object* obj = get_bpf_object(bpf_file);
	map_fd = get_map_fd(obj, "config_map");
	fprintf(stderr, "Map fd: %d\n", map_fd);
	int key = 0;
	bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
	/* Load & verify BPF programs */
	err = tcp_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = tcp_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started!\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	tcp_bpf__destroy(skel);
	return -err;
}
