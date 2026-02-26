Nitriding example
=================

This directory contains an example application; a lightweight
[Go program](service.go)
that retrieves data from an HTTP server.  The project's
[Dockerfile](Dockerfile) adds the nitriding standalone executable along with the
enclave application, consisting of the
[Go program](service.go)
and a
[shell script](start.sh)
that invokes nitriding in the background, followed by running the Go binary.

To build the nitriding executable, the Docker image, the enclave image, and
finally run the enclave image, simply run:

    make

## How to Test

### 1. Local Test Mode (Recommended for Dev)
If you started the service using `./test-local.sh`, use this command:
```bash
curl -k -X POST https://localhost:8443/app/sss/key
```

### 2. Nitro Enclave Mode
If you started the enclave using `./run-enclave.sh`, you need to forward the port first:
```bash
# 1. Forward host port 443 to enclave (one-time setup)
curl --unix-socket /tmp/network.sock http:/unix/services/forwarder/expose \
  -X POST -d '{"local":":443","remote":"192.168.127.2:443"}'

# 2. Access the API
curl -k -X POST https://localhost/app/sss/key
```
