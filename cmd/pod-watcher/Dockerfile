# ---- Builder stage ----
FROM golang:1.24 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy Go module files from the root
COPY go.mod go.sum ./

# Download Go dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build only the pod-watcher binary
RUN CGO_ENABLED=0 GOOS=linux go build -o pod-watcher ./cmd/pod-watcher

# ---- Final stage ----
FROM alpine:latest

WORKDIR /app

# Copy the binary built in the previous stage
COPY --from=builder /app/pod-watcher .

# Run the binary
CMD ["./pod-watcher"]
