# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o log-service .

# Final stage
FROM alpine:latest

# Minimal runtime deps: certs + curl for healthcheck
RUN apk --no-cache add ca-certificates curl

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/log-service .

# Expose port
EXPOSE 8080

# Run the application
CMD ["./log-service"]
