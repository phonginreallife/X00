# KernelSeal All-in-One Demo Image
#
# Bundles the agent, the kernelseal-exec shim, and the BPF programs so the demo
# runs from a single container.
#
# The BPF compile needs bpf/vmlinux.h, which is generated from the host's BTF and
# gitignored. Run `make vmlinux` before building so it is present in the build
# context.
# hadolint global ignore=DL3008

FROM golang:1.26-bookworm AS builder

# hadolint ignore=DL3009
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Fail loudly rather than shipping an image with no BPF objects.
RUN make bpf

RUN CGO_ENABLED=0 go build -ldflags="-X main.Version=demo" -o kernelseal ./cmd && \
    CGO_ENABLED=0 go build -ldflags="-X main.Version=demo" -o kernelseal-exec ./cmd/kernelseal-exec

FROM debian:bookworm-slim

# procps supplies pgrep, wget is used to read the metrics endpoint.
# hadolint ignore=DL3009
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/kernelseal /usr/local/bin/kernelseal
COPY --from=builder /app/kernelseal-exec /usr/local/bin/kernelseal-exec
COPY --from=builder /app/bpf/exec_monitor.bpf.o /bpf/exec_monitor.bpf.o
COPY --from=builder /app/bpf/lsm_file_protect.bpf.o /bpf/lsm_file_protect.bpf.o
COPY demo/demo-app.sh /demo/demo-app.sh
COPY demo/docker-entrypoint.sh /entrypoint.sh

RUN chmod 555 /usr/local/bin/kernelseal /usr/local/bin/kernelseal-exec \
        /demo/demo-app.sh /entrypoint.sh && \
    chmod 444 /bpf/*.bpf.o && \
    mkdir -p /etc/kernelseal /run/kernelseal

EXPOSE 9090

ENTRYPOINT ["/entrypoint.sh"]
