//go:build ignore
#include "vmlinux.h"
#include "common_maps.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} nodeCreationOutput  SEC(".maps");

SEC("uprobe//opt/ros/humble/lib/librmw_implementation.so:rmw_create_node")
int BPF_KPROBE(nodeCreationCount, void *context, const char *name, const char *namespace) {
  struct node_creation_event_t *data;
  data = bpf_ringbuf_reserve(&nodeCreationOutput, sizeof(*data), 0);
  if (!data) {
    return 0;
  }

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
  data->pid = pid;
  data->uid = uid;

  bpf_probe_read_user_str(data->nodeName, sizeof(data->nodeName), name);
  bpf_probe_read_user_str(data->nodeNamespace, sizeof(data->nodeNamespace), namespace);

  bpf_map_update_elem(&pidNodeMap, &pid, data, BPF_ANY);
  bpf_ringbuf_submit(data, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
