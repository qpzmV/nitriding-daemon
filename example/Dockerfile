# A Go base image is enough to build nitriding and our service reproducibly.
# We use a specific instead of the latest image to ensure reproducibility.
FROM golang:1.24.1 as builder

WORKDIR /

# Copy local source code for nitriding daemon.
COPY . /nitriding-daemon
ARG TARGETARCH
RUN ARCH=${TARGETARCH} make -C /nitriding-daemon/ nitriding

# Build our service application.
WORKDIR /app
COPY example/go.mod example/go.sum example/service.go ./
RUN go mod download
RUN CGO_ENABLED=0 go build -o service service.go

# Copy start.sh and set permissions.
COPY example/start.sh /bin/
RUN chown root:root /bin/start.sh
RUN chmod 0755      /bin/start.sh

# Use a minimal base image for the final stage.
FROM alpine:3.19

# Copy all our files to the final image.
COPY --from=builder /nitriding-daemon/nitriding /bin/
COPY --from=builder /app/service /bin/
COPY --from=builder /bin/start.sh /bin/

# Install ca-certificates for HTTPS requests.
RUN apk add --no-cache ca-certificates

CMD ["start.sh"]
