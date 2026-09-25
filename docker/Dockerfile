# Stage 1: Builder
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Install only the tools needed to build the static Go binary.
RUN apk add --no-cache ca-certificates tzdata

# Set GOPROXY for better reliability
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org

# Download dependencies before copying source for better layer caching.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build a static auth server.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" \
    -o /build/auth-server ./main.go

# Stage 2: Runtime
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata wget \
    && addgroup -S app \
    && adduser -S -G app app
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/auth-server .

RUN chown app:app /app/auth-server
USER app

# Expose ports (HTTP + gRPC)
EXPOSE 9000 50051

# Run the binary
CMD ["./auth-server"]