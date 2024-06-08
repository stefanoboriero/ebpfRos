package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type node_creation_counterDataT struct {
	Pid           uint32
	Uid           uint32
	NodeName      [16]uint8
	NodeNamespace [16]uint8
}

type topic_message_counterDataT struct {
	Pid       uint32
	Uid       uint32
	TopicName [32]uint8
}

func main() {
	setupOtelSdk(context.Background())
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go setupNodeCreationCounter(&wg)
	wg.Add(1)
	go setupTopicMessageCounter(&wg)
	log.Println("Setup complete")
	wg.Wait()
}

func setupTopicMessageCounter(wg *sync.WaitGroup) {
	var objs topic_message_counterObjects
	if err := loadTopic_message_counterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ex, _ := link.OpenExecutable("/opt/ros/humble/lib/librmw_implementation.so")
	link, err := ex.Uprobe("rmw_publish", objs.TopicMessageCount, nil)
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()
	stopper := make(chan os.Signal, 5)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ringbuf_reader, err := ringbuf.NewReader(objs.TopicMessageOutput)
	if err != nil {
		log.Fatalf("Error opening ringbuf reader %s", err)
	}
	defer ringbuf_reader.Close()

	go func() {
		<-stopper

		if err := ringbuf_reader.Close(); err != nil {
			log.Fatalf("Error closing ringbuffer, %s", err)
		}
		wg.Done()
	}()

	var meter = otel.Meter("my-service-meter")
	topicMessageCounter, err := meter.Int64Counter("topic.message.sent")
	if err != nil {
		log.Fatalf("Unable to create Otel counter, %s", err)
	}
	log.Println("Waiting for topic messages...")

	var data topic_message_counterDataT
	for {
		record, err := ringbuf_reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("Error reading from reader: %s", err)
			continue
		}
		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("pid: %d\ttopicName: %s\n", data.Pid, data.TopicName)
		topicNameAttribute := attribute.String("topic.name", string(data.TopicName[:]))
		topicMessageCounter.Add(context.TODO(), 1, metric.WithAttributes(topicNameAttribute))
	}
}

func setupNodeCreationCounter(wg *sync.WaitGroup) {
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

	ringbuf_reader, err := ringbuf.NewReader(objs.NodeCreationOutput)
	if err != nil {
		log.Fatalf("Error opening ringbuf reader %s", err)
	}
	defer ringbuf_reader.Close()

	go func() {
		<-stopper

		wg.Done()
		if err := ringbuf_reader.Close(); err != nil {
			log.Fatalf("Error closing ringbuffer, %s", err)
		}
	}()

	var meter = otel.Meter("my-service-meter")
	nodeCounter, err := meter.Int64Counter("node.create")
	if err != nil {
		log.Fatalf("Unable to create Otel counter, %s", err)
	}
	log.Println("Waiting for nodes to be create...")

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

        log.Printf("pid: %d\tnodeName: %s\tnodeNamespace: %s\n", data.Pid, data.NodeName, data.NodeNamespace)
		nodeCounter.Add(context.TODO(), 1)
	}
}
