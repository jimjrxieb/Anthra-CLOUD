# DELIBERATELY INSECURE — runs as root, no multi-stage, no healthcheck
FROM golang:1.22

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o log-ingest .

EXPOSE 9090
CMD ["./log-ingest"]
