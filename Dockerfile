FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY ./go.mod ./go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Coraza waf server binary
RUN go build -o coraza-traefik-middleware ./src

# Use a minimal image for runtime
FROM alpine:3

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/coraza-traefik-middleware .

CMD ["./coraza-traefik-middleware"]