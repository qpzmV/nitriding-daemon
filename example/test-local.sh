#!/bin/bash
set -e

echo "[local] Building binaries..."
make build-local

echo "[local] Starting nitriding in debug mode (port 8443)..."
# Use -debug to bypass enclave-specific requirements
# Use a high port for external since we might not have root
./nitriding \
    -fqdn localhost \
    -ext-pub-port 8443 \
    -intport 8080 \
    -wait-for-app \
    -debug &

NITRIDING_PID=$!

echo "[local] Starting service..."
./service &
SERVICE_PID=$!

cleanup() {
    echo "[local] Shutting down..."
    kill $NITRIDING_PID || true
    kill $SERVICE_PID || true
}

trap cleanup EXIT

echo "[local] Service should be ready soon."
echo "[local] You can test with: curl -k https://localhost:8443/enclave"
echo "[local] Press Ctrl+C to stop."

wait
