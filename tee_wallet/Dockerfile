# Build our service application.
FROM golang:1.24.1 as builder

WORKDIR /app
COPY go.mod go.sum service.go ./
RUN go mod download
RUN CGO_ENABLED=0 go build -o teewallet service.go

# Copy start.sh and set permissions.
COPY start.sh /bin/
RUN chown root:root /bin/start.sh
RUN chmod 0755      /bin/start.sh

# Use a minimal base image for the final stage.
FROM alpine:3.19

# Copy all our files to the final image.
COPY --from=builder /app/teewallet /bin/
COPY --from=builder /bin/start.sh /bin/

# Install ca-certificates for HTTPS requests.
RUN apk add --no-cache ca-certificates

CMD ["start.sh"]
