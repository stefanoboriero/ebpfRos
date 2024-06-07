//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char message[12] = "Hello World";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} output SEC(".maps");

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
};

SEC("uprobe//opt/ros/humble/lib/librmw_implementation.so:rmw_create_node")
int BPF_KPROBE(nodeCreationCount, const void *context, const char *name) {
  struct data_t *data;
  data = bpf_ringbuf_reserve(&output, sizeof(*data), 0);
  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  bpf_get_current_comm(data->command, sizeof(data->command));
  bpf_probe_read_user_str(data->path, sizeof(data->path), name);

  bpf_ringbuf_submit(data, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
