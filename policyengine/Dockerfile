FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY policyengine/ ./policyengine/
RUN CGO_ENABLED=0 go build -o /policyengine ./policyengine/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /policyengine /usr/local/bin/policyengine
ENTRYPOINT ["policyengine"]
