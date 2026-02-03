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
