# ---- Build stage ----
FROM golang:1.24 AS builder

# Set the working directory
WORKDIR /app

# Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the verifier binary (from cmd/verifier if that's where main.go is)
RUN CGO_ENABLED=0 GOOS=linux go build -o verifier ./cmd/verifier

# ---- Runtime stage ----
FROM alpine:latest

# Set the working directory in the runtime container
WORKDIR /app

# Copy the built binary from builder stage
COPY --from=builder /app/verifier .

# Run the binary
CMD ["./verifier"]
