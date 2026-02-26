# syntax=docker/dockerfile:1
#
# Multi-stage build for githttps-proxy
# Designed for Coolify: runs plain HTTP behind its reverse proxy.

FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o githttps-proxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata curl
WORKDIR /app

COPY --from=builder /build/githttps-proxy /usr/local/bin/
COPY docker/entrypoint.sh  /entrypoint.sh
COPY docker/config.default.yaml /app/config.default.yaml
RUN chmod +x /entrypoint.sh && mkdir -p /data/keys /data/config

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["serve", "-config", "/data/config/config.yaml"]
