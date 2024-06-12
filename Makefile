TARGET = ebpf-ros
GOARCH = $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

all: $(TARGET)
.PHONY: all

$(TARGET): vmlinux.h
	GOARCH=$(GOARCH) go generate
	GOARCH=$(GOARCH) go build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(TARGET)
	- rm *_bpfel.go
	- rm *_bpfeb.go
	- rm *_bpfel.o
	- rm *_bpfeb.o
