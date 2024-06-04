package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cflags "-g -O2 -Wall -D __TARGET_ARCH_x86" node_creation_counter node_creation_counter.bpf.c --I node_creation_counter.h
