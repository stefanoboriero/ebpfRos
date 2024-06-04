# eBPF ROS - telemetry instrumentation for ROS2 applications

This work aims at providing an eBPF based telemetry instrumentation leveraging eBPF and exporting telemetry in the OpenTelemetry standard.

## Building the project

Run 'make'

## Execute the project

Run 'sudo ./node_creation_counter'

# TODO
 [] Change from performance array to ringbuffer
 [] Change user space program from C to golang
 [] Export the counter of nodes created as an OpenTelemetry counter
