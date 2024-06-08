//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} nodeCreationOutput  SEC(".maps");

struct data_t {
   int pid;
   int uid;
   char nodeName[16];
   char nodeNamespace[16];
};

SEC("uprobe//opt/ros/humble/lib/librmw_implementation.so:rmw_create_node")
int BPF_KPROBE(nodeCreationCount, void *context, const char *name, const char *namespace) {
  struct data_t *data;
  data = bpf_ringbuf_reserve(&nodeCreationOutput, sizeof(*data), 0);
  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  bpf_probe_read_user_str(data->nodeName, sizeof(data->nodeName), name);
  bpf_probe_read_user_str(data->nodeNamespace, sizeof(data->nodeNamespace), namespace);

  bpf_ringbuf_submit(data, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
