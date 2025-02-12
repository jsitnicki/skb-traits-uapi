#!/bin/bash

set -o xtrace
set -o errexit

readonly BASE_DIR=$(dirname "$0")
readonly XDP_OBJ="${BASE_DIR}/bpf/xdp_pass.bpf.o"

ip link set dev lo xdpgeneric object "${XDP_OBJ}" section xdp

