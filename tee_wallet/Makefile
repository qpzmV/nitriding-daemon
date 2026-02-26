prog := teewallet
version := $(shell git describe --tags --dirty 2>/dev/null || echo "latest")
image_tag := $(prog):$(version)
image_tar := $(prog)-$(version)-kaniko.tar
image_eif := $(image_tar:%.tar=%.eif)

ARCH ?= $(shell uname -m)
ifeq ($(ARCH),aarch64)
	override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
	override ARCH=amd64
endif

.PHONY: all
all: run

.PHONY: image
image: Dockerfile service.go start.sh
	docker build \
		-t $(image_tag) \
		--build-arg TARGETPLATFORM=linux/$(ARCH) \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=$(ARCH) \
		-f Dockerfile .

.PHONY: build-local
build-local:
	go build -o $(prog) service.go

$(image_eif): Dockerfile service.go start.sh
	$(MAKE) image
	nitro-cli build-enclave \
		--docker-uri $(image_tag) \
		--output-file $(image_eif)

# Default values for run target
CID ?= 4
PORT ?= 8088

.PHONY: run
run: $(image_eif)
	# Start our proxy and the enclave.
	./run-enclave.sh $(image_eif) $(CID) $(PORT)

.PHONY: clean
clean:
	rm -f $(image_tar) $(image_eif)
