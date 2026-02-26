#!/bin/bash

# Usage: ./run-enclave.sh IMAGE_EIF [CID] [HOST_PORT]
if [ $# -lt 1 ]
then
	echo >&2 "Usage: $0 IMAGE_EIF [CID] [HOST_PORT]"
	exit 1
fi

image_eif="$1"
cid="${2:-4}"
host_port="${3:-8088}"

# socat bridge to map host TCP port to enclave Vsock port
# We use socat because it's simpler for direct Vsock-to-TCP bridging without a full network stack.
echo "[ec2] Starting socat bridge: localhost:$host_port -> CID $cid : 8080"
sudo socat TCP4-LISTEN:${host_port},reuseaddr,fork VSOCK-CONNECT:${cid}:8080 &
bridge_pid="$!"

# Run enclave in debug mode.
# Removed --attach-console to allow multiple instances to run without blocking.
echo "[ec2] Starting enclave with CID $cid."
nitro-cli run-enclave \
	--cpu-count 2 \
	--memory 600 \
	--enclave-cid "$cid" \
	--eif-path "$image_eif" \
	--debug-mode

# To see the console output, user can run: nitro-cli console --enclave-cid $cid
echo "[ec2] Enclave started. Access via http://localhost:$host_port"
echo "[ec2] Bridge PID: $bridge_pid. Remember to kill it when terminating the enclave."
