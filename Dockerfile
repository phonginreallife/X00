# KernelSeal Multi-stage Dockerfile
# Builds the BPF programs, the privileged agent, and the kernelseal-exec shim.
# hadolint global ignore=DL3008

ARG VERSION=dev
ARG TARGETARCH=amd64

# Stage 1: BPF objects
#
# bpf/vmlinux.h is generated on the CI/release runner from the host BTF and
# passed in the build context. Each platform compiles its own *.bpf.o here.
FROM ubuntu:26.04 AS bpf-builder

# hadolint ignore=DL3009
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY bpf/kernelseal_common.h bpf/*.bpf.c ./bpf/
COPY bpf/vmlinux.h ./bpf/
COPY Makefile ./

ARG TARGETARCH

RUN set -eu; \
    make bpf GOARCH="${TARGETARCH}"; \
    ls -la bpf/*.bpf.o

# Stage 2: Build Go binaries
FROM golang:1.22-alpine AS go-builder
WORKDIR /app

# Copy go mod files first so dependency downloads cache independently of source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION
ARG TARGETARCH

# Both binaries are static: the agent so the runtime image stays minimal, and
# the shim because it is copied into arbitrary application containers.
RUN CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" go build \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o kernelseal ./cmd && \
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" go build \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o kernelseal-exec ./cmd/kernelseal-exec

# Stage 3: Final runtime image
FROM debian:bookworm-slim

ARG VERSION

# hadolint ignore=DL3009
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# KernelSeal needs root for BPF, but the group is used to share the delivery
# socket with an application container running as non-root.
RUN groupadd -r -g 1000 kernelseal && \
    useradd -r -g kernelseal -u 1000 -s /sbin/nologin kernelseal

# /run/kernelseal holds the secret delivery socket. Secrets are never written to
# disk, so there is no secret directory to create.
RUN mkdir -p /etc/kernelseal /var/log/kernelseal /run/kernelseal /bpf \
    && chown -R root:kernelseal /var/log/kernelseal /run/kernelseal \
    && chmod 750 /var/log/kernelseal /run/kernelseal

COPY --from=bpf-builder --chown=root:root /app/bpf/*.bpf.o /bpf/
RUN chmod 444 /bpf/*.bpf.o

COPY --from=go-builder --chown=root:root /app/kernelseal /usr/local/bin/kernelseal
COPY --from=go-builder --chown=root:root /app/kernelseal-exec /usr/local/bin/kernelseal-exec
RUN chmod 555 /usr/local/bin/kernelseal /usr/local/bin/kernelseal-exec

COPY --chown=root:kernelseal examples/config.yaml /etc/kernelseal/config.yaml
RUN chmod 440 /etc/kernelseal/config.yaml

LABEL org.opencontainers.image.title="KernelSeal" \
      org.opencontainers.image.description="Kernel-level secret protection for Kubernetes using eBPF and BPF-LSM" \
      org.opencontainers.image.vendor="KernelSeal" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/phonginreallife/kernelseal" \
      security.privileged="true" \
      security.capabilities="BPF,SYS_ADMIN,PERFMON"

WORKDIR /

# Liveness is checked over HTTP by Kubernetes; this only needs to confirm the
# binary in the image is runnable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/kernelseal", "-version"]

# KernelSeal requires root for BPF operations.
ENTRYPOINT ["/usr/local/bin/kernelseal"]
CMD ["-config=/etc/kernelseal/config.yaml", "-exec-monitor=/bpf/exec_monitor.bpf.o", "-lsm=/bpf/lsm_file_protect.bpf.o"]
