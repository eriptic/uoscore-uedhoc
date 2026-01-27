#!/bin/bash

set -e

MAKE=make
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$SCRIPT_DIR/../../"
SAMPLES_DIR="$ROOT_DIR/samples"

rm -rf "$SAMPLES_DIR/linux_oscore/client/build"
$MAKE -C "$SAMPLES_DIR/linux_oscore/client" -j

rm -rf "$SAMPLES_DIR/linux_oscore/server/build"
$MAKE -C "$SAMPLES_DIR/linux_oscore/server" -j

rm -rf "$SAMPLES_DIR/linux_edhoc/initiator/build"
$MAKE -C "$SAMPLES_DIR/linux_edhoc/initiator" -j

rm -rf "$SAMPLES_DIR/linux_edhoc/responder/build"
$MAKE -C "$SAMPLES_DIR/linux_edhoc/responder" -j

rm -rf "$SAMPLES_DIR/linux_edhoc_oscore/initiator_client/build"
$MAKE -C "$SAMPLES_DIR/linux_edhoc_oscore/initiator_client" -j

rm -rf "$SAMPLES_DIR/linux_edhoc_oscore/responder_server/build"
$MAKE -C "$SAMPLES_DIR/linux_edhoc_oscore/responder_server" -j
