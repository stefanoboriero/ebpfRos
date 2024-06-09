#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __type(key, u32);
  __type(value, struct node_creation_event_t);
} pidNodeMap SEC(".maps");

struct node_creation_event_t {
   u32 pid;
   int uid;
   char nodeName[16];
   char nodeNamespace[16];
};
