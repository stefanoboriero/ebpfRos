package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type node_creation_counterDataT struct {
	Pid     uint32
	Uid     uint32
	Command [16]int8
	Message [12]int8
	Path    [16]uint8
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}
	var objs node_creation_counterObjects
	if err := loadNode_creation_counterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ex, _ := link.OpenExecutable("/opt/ros/humble/lib/librmw_implementation.so")
	link, err := ex.Uprobe("rmw_create_node", objs.NodeCreationCount, nil)
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()
	stopper := make(chan os.Signal, 5)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ringbuf_reader, err := ringbuf.NewReader(objs.Output)
	if err != nil {
		log.Fatalf("Error opening ringbuf reader %s", err)
	}
	defer ringbuf_reader.Close()

	go func() {
		<-stopper

		if err := ringbuf_reader.Close(); err != nil {
			log.Fatalf("Error closing ringbuffer, %s", err)
		}
	}()

	log.Println("Waiting for events...")

	var data node_creation_counterDataT
	for {
		record, err := ringbuf_reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("pid: %d\tcomm: %s\n", data.Pid, data.Path)
	}
}
