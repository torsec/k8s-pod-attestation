# ---- Build stage ----
FROM golang:1.24 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the Go application (specifically the registrar command)
RUN CGO_ENABLED=0 GOOS=linux go build -o registrar ./cmd/registrar

# ---- Runtime stage ----
FROM alpine:latest

# Install SQLite and CA certificates
RUN apk add --no-cache sqlite ca-certificates

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/registrar .

# Expose the application's port
EXPOSE 8080

# Run the registrar binary
CMD ["./registrar"]
