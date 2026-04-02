FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY upstream/ ./upstream/
RUN CGO_ENABLED=0 go build -o /upstream ./upstream/

FROM alpine:3.21
COPY --from=builder /upstream /usr/local/bin/upstream
ENTRYPOINT ["upstream"]
