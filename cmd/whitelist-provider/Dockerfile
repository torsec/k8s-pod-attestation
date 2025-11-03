# ---- Stage 1: Build the Go application ----
FROM golang:1.24 AS builder

# Set the working directory
WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -o whitelist ./cmd/whitelist-provider

# ---- Stage 2: Run the application ----
FROM alpine:latest

# Install MongoDB client and bash (optional for debugging)
RUN apk add --no-cache mongodb-tools bash

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/whitelist .

# Set environment variable for MongoDB connection
ENV MONGODB_URI="mongodb://mongo:27017"

# Expose application port
EXPOSE 8080

# Run the service
CMD ["./whitelist"]
