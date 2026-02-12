# Multi-stage Dockerfile for building mock device login pages
# Usage: docker build --build-arg DEVICE=router -t mock-router .

ARG DEVICE=generic

FROM golang:1.24-alpine AS builder

ARG DEVICE

WORKDIR /app

# Copy only the specific device mock
COPY ${DEVICE}/main.go .

# Build the mock server
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o mock-server main.go

# Final minimal image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/mock-server .

ENV PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["./mock-server"]
