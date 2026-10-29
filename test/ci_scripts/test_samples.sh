#!/bin/bash

# Builds every Linux sample as a standalone CMake project.

set -e

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$SCRIPT_DIR/../../"
SAMPLES_DIR="$ROOT_DIR/samples"

for sample in \
	linux_oscore/client \
	linux_oscore/server \
	linux_edhoc/initiator \
	linux_edhoc/responder \
	linux_edhoc_oscore/initiator_client \
	linux_edhoc_oscore/responder_server
do
	echo "=== $sample"
	rm -rf "$SAMPLES_DIR/$sample/build"
	cmake -S "$SAMPLES_DIR/$sample" -B "$SAMPLES_DIR/$sample/build" -G Ninja
	cmake --build "$SAMPLES_DIR/$sample/build"
done
