FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ext_proc/ ./ext_proc/
RUN CGO_ENABLED=0 go build -o /ext_proc ./ext_proc/

FROM alpine:3.21
COPY --from=builder /ext_proc /usr/local/bin/ext_proc
ENTRYPOINT ["ext_proc"]
