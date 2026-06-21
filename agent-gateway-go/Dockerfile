FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY ./go.mod ./
COPY ./cmd ./cmd
COPY ./internal ./internal
RUN go build -trimpath -ldflags='-s -w' -o /out/agent-gateway-go ./cmd/agent-gateway-go

FROM alpine:3.20
RUN adduser -D -H -u 10001 appuser
USER appuser
ARG PORT=8787
ENV PORT=${PORT}
EXPOSE ${PORT}
COPY --from=builder /out/agent-gateway-go /usr/local/bin/agent-gateway-go
ENTRYPOINT ["agent-gateway-go"]
