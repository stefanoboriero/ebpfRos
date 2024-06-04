
//go:build ignore
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "node_creation_counter.h"
#include "node_creation_counter.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct data_t *m = data;

	printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
    return 0;
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    struct node_creation_counter_bpf *skel;
    int err;
	struct ring_buffer *rb = NULL;

	libbpf_set_print(libbpf_print_fn);

	skel = node_creation_counter_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = node_creation_counter_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		node_creation_counter_bpf__destroy(skel);
        return 1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.output), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		node_creation_counter_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	node_creation_counter_bpf__destroy(skel);
	return -err;
}
