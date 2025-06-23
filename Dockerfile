FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o x00 ./cmd/main.go

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y iproute2
COPY --from=builder /app/x00 /x00
COPY bpf/exec_monitor.bpf.o /bpf/
ENTRYPOINT ["/x00"]
