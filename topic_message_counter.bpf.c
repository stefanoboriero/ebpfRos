//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} topicMessageOutput SEC(".maps");

struct topic_message_t {
  int pid;
  int uid;
  char topicName[32];
};

typedef struct rmw_publisher_t {
  const char *implementation_identifier;
  void *data;
  const char *topic_name;
} rmw_publisher_t; // TODO this should be imported via rmw/types.h header, not copy pasted

SEC("uprobe//opt/ros/humble/lib/librmw_implementation.so:rmw_publish")
int BPF_KPROBE(topicMessageCount, const rmw_publisher_t *publisher) {
  struct topic_message_t *data;
  struct rmw_publisher_t p = {};
  data = bpf_ringbuf_reserve(&topicMessageOutput, sizeof(*data), 0);
  if (!data) {
    return 0;
  }

  data->pid = bpf_get_current_pid_tgid() >> 32;
  data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  if (publisher != 0) {
    bpf_probe_read_user(&p, sizeof(p), publisher);
    bpf_probe_read_user_str(data->topicName, sizeof(data->topicName), p.topic_name);
    bpf_ringbuf_submit(data, 0);
  } else {
    bpf_printk("Could not resolve publisher info");
    bpf_ringbuf_discard(data, 0);
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
