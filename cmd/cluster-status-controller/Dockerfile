# ---- Builder stage ----
FROM golang:1.24 AS builder

WORKDIR /app

# Copy module files from project root
COPY go.mod go.sum ./
RUN go mod download

# Copy all source code
COPY . .

# Build only the cluster-status-controller binary
RUN CGO_ENABLED=0 GOOS=linux go build -o cluster-status-controller ./cmd/cluster-status-controller

# ---- Final stage ----
FROM alpine:latest

WORKDIR /app
COPY --from=builder /app/cluster-status-controller .

CMD ["./cluster-status-controller"]
