//go:build ignore
#include "common_maps.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} topicMessageOutput SEC(".maps");

struct message_sent_event_t {
  int pid;
  int uid;
  char topicName[32];
  char publisherNodeName[16];
  char publisherNodeNamespace[16];
};

typedef struct rmw_publisher_t {
  const char *implementation_identifier;
  void *data;
  const char *topic_name;
} rmw_publisher_t; // TODO this should be imported via rmw/types.h header, not copy pasted

SEC("uprobe//opt/ros/humble/lib/librmw_implementation.so:rmw_publish")
int BPF_KPROBE(topicMessageCount, const rmw_publisher_t *publisher) {
  struct message_sent_event_t *data;
  struct node_creation_event_t *senderNode;
  struct rmw_publisher_t p = {};
  data = bpf_ringbuf_reserve(&topicMessageOutput, sizeof(*data), 0);
  if (!data) {
    return 0;
  }

  u32 pid = bpf_get_current_pid_tgid() >> 32;
  data->pid = pid;
  data->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  if (publisher != 0) {
    bpf_probe_read_user(&p, sizeof(p), publisher);
    bpf_probe_read_user_str(data->topicName, sizeof(data->topicName), p.topic_name);
    senderNode = bpf_map_lookup_elem(&pidNodeMap, &pid);
    if (senderNode != 0) {
      bpf_probe_read_kernel(data->publisherNodeName, sizeof(data->publisherNodeName), senderNode->nodeName);
      bpf_probe_read_kernel(data->publisherNodeNamespace, sizeof(data->publisherNodeName), senderNode->nodeNamespace);
    } else {
      bpf_probe_read_kernel(data->publisherNodeName, sizeof(data->publisherNodeName), "UNKNOWN");
      bpf_probe_read_kernel(data->publisherNodeNamespace, sizeof(data->publisherNodeName), "UNKNOWN");
    }
    bpf_ringbuf_submit(data, 0);
  } else {
    bpf_printk("Could not resolve publisher info");
    bpf_ringbuf_discard(data, 0);
  }
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
