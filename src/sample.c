/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "Sample XDP program\n";

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include "sample.skel.h"


struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IF_NAMESIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char src_mac[18];
	char dest_mac[18];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
};

struct option_wrapper {
	struct option option;
	char *help;
	char *metavar;
	bool required;
};

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

int verbose = 1;

#define BUFSIZE 30

void _print_options(const struct option_wrapper *long_options, bool required)
{
	int i, pos;
	char buf[BUFSIZE];

	for (i = 0; long_options[i].option.name != 0; i++) {
		if (long_options[i].required != required)
			continue;

		if (long_options[i].option.val > 64) /* ord('A') = 65 */
			printf(" -%c,", long_options[i].option.val);
		else
			printf("    ");
		pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
		if (long_options[i].metavar)
			snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);
		printf("%-22s", buf);
		printf("  %s", long_options[i].help);
		printf("\n");
	}
}

void usage(const char *prog_name, const char *doc,
	const struct option_wrapper *long_options, bool full)
{
	printf("Usage: %s [options]\n", prog_name);

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	printf("\nDOCUMENTATION:\n %s\n", doc);
	printf("Required options:\n");
	_print_options(long_options, true);
	printf("\n");
	printf("Other options:\n");
	_print_options(long_options, false);
	printf("\n");
}

int option_wrappers_to_options(const struct option_wrapper *wrapper,
			struct option **options)
{
	int i, num;
	struct option *new_options;
	for (i = 0; wrapper[i].option.name != 0; i++) {}
	num = i;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	for (i = 0; i < num; i++) {
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
	}

	*options = new_options;
	return 0;
}

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
                        struct config *cfg, const char *doc)
{
	struct option *long_options;
	bool full_help = false;
	int longindex = 0;
	char *dest;
	int opt;

	if (option_wrappers_to_options(options_wrapper, &long_options)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAIL_OPTION);
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hd:r:L:R:ASNFUMQ:czpq",
						long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			cfg->ifname = (char *)&cfg->ifname_buf;
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);
			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'r':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --redirect-dev name too long\n");
				goto error;
			}
			cfg->redirect_ifname = (char *)&cfg->redirect_ifname_buf;
			strncpy(cfg->redirect_ifname, optarg, IF_NAMESIZE);
			cfg->redirect_ifindex = if_nametoindex(cfg->redirect_ifname);
			if (cfg->redirect_ifindex == 0) {
				fprintf(stderr,
					"ERR: --redirect-dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'A':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			break;
		case 'S':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'N':
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
			break;
		case 3: /* --offload-mode */
			cfg->xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
			cfg->xdp_flags |= XDP_FLAGS_HW_MODE;   /* Set   flag */
			break;
		case 'F':
			cfg->xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'M':
			cfg->reuse_maps = true;
			break;
		case 'U':
			cfg->do_unload = true;
			break;
		case 'p':
			cfg->xsk_poll_mode = true;
			break;
		case 'q':
			verbose = false;
			break;
		case 'Q':
			cfg->xsk_if_queue = atoi(optarg);
			break;
		case 1: /* --filename */
			dest  = (char *)&cfg->filename;
			strncpy(dest, optarg, sizeof(cfg->filename));
			break;
		case 2: /* --progsec */
			dest  = (char *)&cfg->progsec;
			strncpy(dest, optarg, sizeof(cfg->progsec));
			break;
		case 'L': /* --src-mac */
			dest  = (char *)&cfg->src_mac;
			strncpy(dest, optarg, sizeof(cfg->src_mac));
			break;
		case 'R': /* --dest-mac */
			dest  = (char *)&cfg->dest_mac;
			strncpy(dest, optarg, sizeof(cfg->dest_mac));
			break;
		case 'c':
			cfg->xsk_bind_flags &= XDP_ZEROCOPY;
			cfg->xsk_bind_flags |= XDP_COPY;
			break;
		case 'z':
			cfg->xsk_bind_flags &= XDP_COPY;
			cfg->xsk_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'h':
			full_help = true;
			/* fall-through */
		error:
		default:
			usage(argv[0], doc, options_wrapper, full_help);
			free(long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
	free(long_options);
}

static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{0, 0, NULL,  0 }, NULL, false}
};

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

int load_bpf_object_file__simple(const char *filename)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}

	/* Simply return the first program file descriptor.
	 * (Hint: This will get more advanced later)
	 */
	return first_prog_fd;
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags)
{
	/* Next assignment this will move into ../common/
	 * (in more generic version)
	 */
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return EXIT_FAIL_XDP;
	}
	return EXIT_OK;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	/* Next assignment this will move into ../common/ */
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}

	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return EXIT_FAIL_XDP;
	}

	return EXIT_OK;
}

int main(int argc, char **argv)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char filename[256] = "sample.o";
	struct sample_bpf *skel;
	int prog_fd, err;
	struct bpf_program *trace_prog_fentry;
	struct bpf_object *trace_obj = NULL;
	struct bpf_link *trace_link_fentry = NULL;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};

	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags);

	/* Load the BPF-ELF object file and get back first BPF_prog FD */
	prog_fd = load_bpf_object_file__simple(filename);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: loading file: %s\n", filename);
		return EXIT_FAIL_BPF;
	}

	/* At this point: BPF-prog is (only) loaded by the kernel, and prog_fd
	 * is our file-descriptor handle. Next step is attaching this FD to a
	 * kernel hook point, in this case XDP net_device link-level hook.
	 * Fortunately libbpf have a helper for this:
	 */
	err = xdp_link_attach(cfg.ifindex, cfg.xdp_flags, prog_fd);
	if (err)
		return err;

	trace_obj = bpf_object__open_file("instrument.o", NULL);
	trace_prog_fentry = bpf_object__find_program_by_name(trace_obj,
							     "trace_on_entry");
	if (!trace_prog_fentry) {
		fprintf(stderr, "ERR: Can't find XDP trace fentry function!\n");
		goto error_exit;
	}
	bpf_program__set_expected_attach_type(trace_prog_fentry,
					      BPF_TRACE_FENTRY);
	bpf_program__set_attach_target(trace_prog_fentry,
				       prog_fd,
		                       "myfunc");
	err = bpf_object__load(trace_obj);
	if (err) {
		fprintf(stderr, "ERR: Couldn't load the tracer\n");
	}
	trace_link_fentry = bpf_program__attach_trace(trace_prog_fentry);
	err = libbpf_get_error(trace_link_fentry);
	if (err) {
		fprintf(stderr,
			"ERROR: Can't attach XDP trace fentry function: %s\n",
			strerror(-err));
		goto error_exit;
	}

        /* This step is not really needed , BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	printf("Success: Loading "
		"XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
		info.name, info.id, cfg.ifname, cfg.ifindex);
	return EXIT_OK;

error_exit:
	bpf_link__destroy(trace_link_fentry);
	bpf_object__close(trace_obj);
	return EXIT_OK;
}
