// go:build ignore

#include "node_creation_counter.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char message[12] = "Hello World";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} output SEC(".maps");

struct user_msg_t {
  char message[12];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);
  __type(value, struct user_msg_t);
} my_config SEC(".maps");

SEC("uprobe//opt/ros/humble/lib/librmw_implementation.so:rmw_create_node")
int BPF_KPROBE(nodeCreationCount, const void *context, const char *name) {
  struct user_msg_t *p;
  struct data_t *data;
  data = bpf_ringbuf_reserve(&output, sizeof(*data), 0);
  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  bpf_get_current_comm(data->command, sizeof(data->command));
  bpf_probe_read_user_str(data->path, sizeof(data->path), name);

  p = bpf_map_lookup_elem(&my_config, &data->uid);
  if (p != 0) {
    bpf_probe_read_kernel_str(data->message, sizeof(data->message), p->message);
  } else {
    bpf_probe_read_kernel_str(data->message, sizeof(data->message), message);
  }

  bpf_ringbuf_submit(data, 0);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
