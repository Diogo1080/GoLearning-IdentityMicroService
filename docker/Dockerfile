# Stage 1: Builder
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Install build dependencies with CGO support
RUN apk add --no-cache gcc musl-dev git ca-certificates tzdata

# Set GOPROXY for better reliability
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org

# Copy EVERYTHING from project root (includes go.mod, go.sum, cmd/, internal/, etc.)
COPY . .

# Build only auth-server
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" \
    -o /build/auth-server ./main.go

# Stage 2: Runtime
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/auth-server .

# Create data directory (if needed)
RUN mkdir -p /data

# Expose ports (HTTP + gRPC)
EXPOSE 8080 50051

# Run the binary
CMD ["./auth-server"]