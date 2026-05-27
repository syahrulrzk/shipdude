# syntax=docker/dockerfile:1

# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Cache dependency downloads separately from source compilation
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a fully static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o shipdude .

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates needed for HTTPS calls to GitHub API
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/shipdude .

# Ensure config directory exists (mounted as volume at runtime)
RUN mkdir -p /app/config

EXPOSE 8080

ENTRYPOINT ["/app/shipdude"]
