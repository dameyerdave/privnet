# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/privnet ./cmd/privnet

FROM alpine:3.22
# iproute2: interface/address/route management; iptables: per-network isolation.
RUN apk add --no-cache iproute2 iptables ca-certificates wireguard-tools-wg
COPY --from=build /out/privnet /usr/local/bin/privnet
ENV DB_PATH=/data/privnet.db LISTEN_ADDR=:8080
VOLUME /data
EXPOSE 8080/tcp 51820/udp
ENTRYPOINT ["/usr/local/bin/privnet"]
