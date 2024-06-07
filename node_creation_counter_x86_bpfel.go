// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadNode_creation_counter returns the embedded CollectionSpec for node_creation_counter.
func loadNode_creation_counter() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Node_creation_counterBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load node_creation_counter: %w", err)
	}

	return spec, err
}

// loadNode_creation_counterObjects loads node_creation_counter and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*node_creation_counterObjects
//	*node_creation_counterPrograms
//	*node_creation_counterMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadNode_creation_counterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadNode_creation_counter()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// node_creation_counterSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type node_creation_counterSpecs struct {
	node_creation_counterProgramSpecs
	node_creation_counterMapSpecs
}

// node_creation_counterSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type node_creation_counterProgramSpecs struct {
	NodeCreationCount *ebpf.ProgramSpec `ebpf:"nodeCreationCount"`
}

// node_creation_counterMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type node_creation_counterMapSpecs struct {
	Output *ebpf.MapSpec `ebpf:"output"`
}

// node_creation_counterObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadNode_creation_counterObjects or ebpf.CollectionSpec.LoadAndAssign.
type node_creation_counterObjects struct {
	node_creation_counterPrograms
	node_creation_counterMaps
}

func (o *node_creation_counterObjects) Close() error {
	return _Node_creation_counterClose(
		&o.node_creation_counterPrograms,
		&o.node_creation_counterMaps,
	)
}

// node_creation_counterMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadNode_creation_counterObjects or ebpf.CollectionSpec.LoadAndAssign.
type node_creation_counterMaps struct {
	Output *ebpf.Map `ebpf:"output"`
}

func (m *node_creation_counterMaps) Close() error {
	return _Node_creation_counterClose(
		m.Output,
	)
}

// node_creation_counterPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadNode_creation_counterObjects or ebpf.CollectionSpec.LoadAndAssign.
type node_creation_counterPrograms struct {
	NodeCreationCount *ebpf.Program `ebpf:"nodeCreationCount"`
}

func (p *node_creation_counterPrograms) Close() error {
	return _Node_creation_counterClose(
		p.NodeCreationCount,
	)
}

func _Node_creation_counterClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed node_creation_counter_x86_bpfel.o
var _Node_creation_counterBytes []byte
