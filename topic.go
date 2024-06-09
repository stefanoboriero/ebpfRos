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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type topic_message_counterMessageSentEventT struct {
	Pid                    int32
	Uid                    int32
	TopicName              [32]uint8
	PublisherNodeName      [16]uint8
	PublisherNodeNamespace [16]uint8
}

func setupTopicMessageCounter(wg *sync.WaitGroup) {
	var objs topic_message_counterObjects
	if err := loadTopic_message_counterObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/",
		}}); err != nil {
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

	var data topic_message_counterMessageSentEventT
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

		log.Printf("pid: %d\ttopicName: %s\tsender: %s\n", data.Pid, data.TopicName, data.PublisherNodeName)
		topicNameAttribute := attribute.String("topic.name", string(data.TopicName[:]))
		publisherNodeNameAttribute := attribute.String("publisher.node.name", string(data.PublisherNodeName[:]))
		publisherNodeNamespaceAttribute := attribute.String("publisher.node.namespace", string(data.PublisherNodeNamespace[:]))
		topicMessageCounter.Add(context.TODO(), 1, metric.WithAttributes(topicNameAttribute,
			publisherNodeNameAttribute, publisherNodeNamespaceAttribute))
	}
}
