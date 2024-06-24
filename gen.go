package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" node_creation_counter node_creation_counter.bpf.c --I node_creation_counter.h

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" topic_message_counter topic_message_counter.bpf.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" message_taken message_taken.bpf.c

