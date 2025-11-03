# ---- Builder stage ----
FROM golang:1.24 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy Go module files from the project root
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build only the pod-handler binary
RUN CGO_ENABLED=0 GOOS=linux go build -o pod-handler ./cmd/pod-handler

# ---- Final image ----
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/pod-handler .

# Expose port if your app listens on it
EXPOSE 8080

# Run the binary
CMD ["./pod-handler"]
