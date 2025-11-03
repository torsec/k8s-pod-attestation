# ---- Builder stage ----
FROM golang:1.24 AS builder

# Install OpenSSL library before building
RUN apt-get update && apt-get install -y libssl-dev

# Set the working directory inside the container
WORKDIR /app

# Copy Go module files from the project root (two levels up)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire project source
COPY ../.. .

# Build the agent binary
RUN CGO_ENABLED=1 GOOS=linux go build -o agent ./cmd/agent

# ---- Runtime stage ----
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/agent .

# Set library path for OpenSSL
ENV LD_LIBRARY_PATH=/usr/lib:/usr/local/lib

# Run the agent
CMD ["./agent"]
