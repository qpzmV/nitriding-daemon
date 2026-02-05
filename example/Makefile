prog := go-enclave
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
image: $(image_tar)

$(image_tar): Dockerfile service.go start.sh
	docker build \
		-t $(image_tag) \
		--build-arg TARGETPLATFORM=linux/$(ARCH) \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH=$(ARCH) \
		-f Dockerfile ..
	# Save the image to a tarball for nitro-cli if needed, 
	# but nitro-cli can also use the local docker image directly.
	docker save $(image_tag) > $(image_tar)

.PHONY: build-local
build-local:
	go build -o service service.go
	make -C .. nitriding
	cp ../nitriding .

$(image_eif): $(image_tar)
	docker load -i $<
	nitro-cli build-enclave \
		--docker-uri $(image_tag) \
		--output-file $(image_eif)

.PHONY: run
run: $(image_eif)
	# Terminate already-running enclave.
	nitro-cli terminate-enclave --all
	# Start our proxy and the enclave.
	./run-enclave.sh $(image_eif)

.PHONY: clean
clean:
	rm -f $(image_tar) $(image_eif)
