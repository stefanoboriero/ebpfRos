package main

import (
	"context"
	"log"
	"sync"

	"github.com/cilium/ebpf/rlimit"
)


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
	wg.Add(1)
	go setupMessageTakenCounter(&wg)
	log.Println("Setup complete")
	wg.Wait()
}

