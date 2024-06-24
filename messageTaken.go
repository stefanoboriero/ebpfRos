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

type MessageTakenEventT struct {
	Pid                     int32
	Uid                     int32
	TopicName               [32]uint8
	SubscriberNodeName      [16]uint8
	SubscriberNodeNamespace [16]uint8
}

func setupMessageTakenCounter(wg *sync.WaitGroup) {
	var objs message_takenObjects
	if err := loadMessage_takenObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/",
		}}); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ex, _ := link.OpenExecutable("/opt/ros/humble/lib/librmw_implementation.so")
	link, err := ex.Uprobe("rmw_take_with_info", objs.MessageTaken, nil)
	if err != nil {
		log.Fatal("Attaching callback execution:", err)
	}
	defer link.Close()
	stopper := make(chan os.Signal, 5)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ringbuf_reader, err := ringbuf.NewReader(objs.MessageTakenOutput)
	if err != nil {
		log.Fatalf("Error opening ringbuf reader %s", err)
	}
	defer ringbuf_reader.Close()

	go func() {
		<-stopper

		if err := ringbuf_reader.Close(); err != nil {
			log.Fatalf("Error closing ringbuf reader %s", err)
		}
		wg.Done()
	}()

	log.Println("Waiting for callback executions...")

	var meter = otel.Meter("my-service-meter")
	messageTakenCounter, err := meter.Int64Counter("topic.message.taken")
	if err != nil {
		log.Fatalf("Unable to create Otel counter, %s", err)
	}
	log.Println("Waiting for topic messages...")

	var data MessageTakenEventT
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

		log.Printf("Processing message taken event pid: %d\ttopicName: %s\tsender: %s\n", data.Pid, data.TopicName, data.SubscriberNodeName)
		topicNameAttribute := attribute.String("topic.name", string(data.TopicName[:]))
		subscriberNodeNameAttribute := attribute.String("subscriber.node.name", string(data.SubscriberNodeName[:]))
		subscriberNodeNamespaceAttribute := attribute.String("subscriber.node.namespace", string(data.SubscriberNodeNamespace[:]))
		messageTakenCounter.Add(context.TODO(), 1, metric.WithAttributes(topicNameAttribute,
			subscriberNodeNameAttribute, subscriberNodeNamespaceAttribute))

	}
}
