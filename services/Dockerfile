FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o log-ingest .

FROM alpine:3.19

RUN addgroup -S appgroup && adduser -S -G appgroup -u 10001 appuser
COPY --from=builder /app/log-ingest /usr/local/bin/log-ingest

USER 10001

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:9090/health"]

CMD ["log-ingest"]
