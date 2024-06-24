//go:build ignore
#include "common_maps.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// TODO include these types definitions from ROS rmw types header
typedef struct rmw_subscription_options_t {
  void *rmw_specific_subscription_payload;
  bool ignore_local_publications;
} rmw_subscription_options_t;

typedef struct rmw_subscription_t {
  const char *implementation_identifier;
  void *data;
  const char *topic_name;
  rmw_subscription_options_t options;
  bool can_loan_messages;
} rmw_subscription_t;

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} messageTakenOutput SEC(".maps");

struct message_taken_event_t {
  int pid;
  int uid;
  char topicName[32];
  char subscriberNodeName[16];
  char subscriberNodeNamespace[16];
};

SEC("uprobe//opt/ros/humble/lib/librmw_implementation.so:take_with_info")
int BPF_KPROBE(messageTaken, const rmw_subscription_t *subscription) {
  struct node_creation_event_t *subscriberNode;
  struct message_taken_event_t *messageTakenEvent;
  struct rmw_subscription_t subscriptionCopy = {};
  messageTakenEvent = bpf_ringbuf_reserve(&messageTakenOutput, sizeof(*messageTakenEvent), 0);
  if (!messageTakenEvent) {
      return 0;
  }

  u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  subscriberNode = bpf_map_lookup_elem(&pidNodeMap, &pid);
  if (subscription != 0) {
    bpf_probe_read_user(&subscriptionCopy, sizeof(subscriptionCopy), subscription);
    bpf_probe_read_user_str(messageTakenEvent->topicName, sizeof(messageTakenEvent->topicName),
                            subscriptionCopy.topic_name);
    if (subscriberNode != 0) {
      bpf_probe_read_kernel(messageTakenEvent->subscriberNodeName, sizeof(messageTakenEvent->subscriberNodeName),
                            subscriberNode->nodeName);
      bpf_probe_read_kernel(messageTakenEvent->subscriberNodeNamespace,
                            sizeof(messageTakenEvent->subscriberNodeNamespace), subscriberNode->nodeNamespace);

      messageTakenEvent->pid = pid;
      messageTakenEvent->uid = uid;
      bpf_ringbuf_submit(messageTakenEvent, 0);
    } else {
      bpf_printk("Could not resolve subscriber info");
      bpf_ringbuf_discard(messageTakenEvent, 0);
    }
  } else {
      bpf_ringbuf_discard(messageTakenEvent, 0);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
