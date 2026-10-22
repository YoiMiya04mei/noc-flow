FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod ./
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /collector cmd/collector/main.go

FROM alpine:3.20

RUN apk --no-cache add ca-certificates wget

WORKDIR /app
COPY --from=builder /collector /app/collector

EXPOSE 2055/udp 6343/udp 4739/udp 8081

ENTRYPOINT ["/app/collector"]
