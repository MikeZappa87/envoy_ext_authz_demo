FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY ext_authz/ ./ext_authz/
RUN CGO_ENABLED=0 go build -o /ext_authz ./ext_authz/

FROM alpine:3.21
COPY --from=builder /ext_authz /usr/local/bin/ext_authz
ENTRYPOINT ["ext_authz"]
