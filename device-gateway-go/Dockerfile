FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY ./go.mod ./
COPY ./cmd ./cmd
COPY ./internal ./internal
RUN go build -trimpath -ldflags='-s -w' -o /out/device-gateway-go ./cmd/device-gateway-go

FROM alpine:3.20
RUN adduser -D -H -u 10001 appuser
USER appuser
ARG PORT=8787
ENV PORT=${PORT}
EXPOSE ${PORT}
COPY --from=builder /out/device-gateway-go /usr/local/bin/device-gateway-go
ENTRYPOINT ["device-gateway-go"]
