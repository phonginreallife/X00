# KernelSeal Makefile - Build eBPF programs and Go binaries
#
# Requirements:
# - clang >= 11 (for BPF compilation)
# - llvm >= 11 (for llvm-strip)
# - libbpf-dev
# - bpftool (for vmlinux.h generation)

SHELL := /bin/bash

# Version stamped into both binaries. Override with: make VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Go settings. GOARCH is overridable so arm64 images can be built.
GO := go
GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED := 0

# Map the Go arch onto the __TARGET_ARCH_* macro libbpf expects.
BPF_TARGET_ARCH_amd64 := x86
BPF_TARGET_ARCH_arm64 := arm64
BPF_TARGET_ARCH := $(BPF_TARGET_ARCH_$(GOARCH))
ifeq ($(BPF_TARGET_ARCH),)
$(error Unsupported GOARCH "$(GOARCH)": expected amd64 or arm64)
endif

# BPF settings
CLANG := clang
LLVM_STRIP := llvm-strip
BPFTOOL := bpftool

KERNEL_VERSION := $(shell uname -r)

# Directories
BPF_DIR := bpf
BUILD_DIR := build
CMD_DIR := cmd

BPF_CFLAGS := -g -O2 -target bpf \
	-D__TARGET_ARCH_$(BPF_TARGET_ARCH) \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	-I$(BPF_DIR)

BPF_SOURCES := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJECTS := $(BPF_SOURCES:.c=.o)

# Binaries: the privileged agent, and the unprivileged exec shim that runs
# inside the application container.
BINARY := kernelseal
SHIM := kernelseal-exec

GO_LDFLAGS := -w -s -X main.Version=$(VERSION)

# Container settings
REGISTRY ?= your-registry
IMAGE_NAME := kernelseal
IMAGE_TAG ?= latest

.PHONY: all
all: vmlinux bpf build

.PHONY: vmlinux
vmlinux: $(BPF_DIR)/vmlinux.h

$(BPF_DIR)/vmlinux.h:
	@echo "Generating vmlinux.h from kernel BTF..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "BTF not available at /sys/kernel/btf/vmlinux"; \
		echo "Build the BPF objects in a container instead: make docker-dev"; \
		exit 1; \
	fi

.PHONY: bpf
bpf: $(BPF_OBJECTS)
	@echo "BPF programs compiled for $(BPF_TARGET_ARCH)"

$(BPF_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(BPF_DIR)/vmlinux.h $(BPF_DIR)/kernelseal_common.h
	@echo "Compiling $<..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

.PHONY: build
build: build-agent build-shim

.PHONY: build-agent
build-agent:
	@echo "Building $(BINARY) $(VERSION) ($(GOOS)/$(GOARCH))..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build -ldflags="$(GO_LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./$(CMD_DIR)
	@echo "Built $(BUILD_DIR)/$(BINARY)"

# The shim is injected into application containers via a shared volume, so it is
# always built static and dependency-free.
.PHONY: build-shim
build-shim:
	@echo "Building $(SHIM) $(VERSION) ($(GOOS)/$(GOARCH))..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		$(GO) build -ldflags="$(GO_LDFLAGS)" -o $(BUILD_DIR)/$(SHIM) ./$(CMD_DIR)/$(SHIM)
	@echo "Built $(BUILD_DIR)/$(SHIM)"

.PHONY: docker
docker:
	@echo "Building Docker image..."
	docker build --build-arg VERSION=$(VERSION) --build-arg TARGETARCH=$(GOARCH) \
		-t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: docker-dev
docker-dev:
	@echo "Building BPF objects in the Cilium builder image..."
	docker run --rm -v $(PWD):/app -w /app \
		--privileged \
		docker.io/cilium/ebpf-builder:1698931239 \
		make bpf GOARCH=$(GOARCH)
	$(MAKE) build
	docker build --build-arg VERSION=$(VERSION) -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) .

.PHONY: test
test:
	@echo "Running unit tests..."
	$(GO) test -race ./internal/...

# The shim delivery tests exercise the real socket handshake and need no
# privileges, so they belong in the default verification path.
.PHONY: test-delivery
test-delivery:
	@echo "Running secret delivery tests..."
	$(GO) test -race -run TestShimDelivery ./test/integration/...

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./internal/...
	$(GO) tool cover -func=coverage.out
	@echo "Coverage report: coverage.out"

.PHONY: test-coverage-html
test-coverage-html: test-coverage
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "HTML report: coverage.html"

.PHONY: test-short
test-short:
	$(GO) test -short ./internal/...

# The LSM enforcement tests need root and a kernel booted with bpf in its lsm=
# list. They skip when those are missing rather than failing.
.PHONY: test-integration
test-integration: bpf
	@echo "Running integration tests (requires root for the LSM cases)..."
	sudo $(GO) test -v ./test/integration/...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: lint-fix
lint-fix:
	golangci-lint run --fix ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...
	goimports -w .

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: security
security:
	gosec ./...

# Verifies the Go structs still match the C definitions in
# bpf/kernelseal_common.h. A drift here is silent at runtime, so it is checked
# explicitly rather than left to chance.
.PHONY: abi-check
abi-check: bpf
	@echo "Checking BPF/Go ABI agreement..."
	$(GO) test -run 'TestABI' -v ./internal/types/
	@echo "Checking BPF program and map names match the loader..."
	$(GO) test -run 'TestSpec' -v ./internal/bpf/

.PHONY: verify
verify: fmt-check vet abi-check test test-delivery
	@echo "All checks passed"

.PHONY: fmt-check
fmt-check:
	@echo "Checking formatting..."
	@unformatted=$$(gofmt -l . 2>/dev/null); \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: clean-bpf
clean-bpf:
	rm -f $(BPF_DIR)/*.bpf.o

.PHONY: clean
clean: clean-bpf
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

.PHONY: clean-all
clean-all: clean
	rm -f $(BPF_DIR)/vmlinux.h

.PHONY: install-deps
install-deps:
	apt-get update && apt-get install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-headers-$(KERNEL_VERSION) \
		bpftool

.PHONY: verify-bpf
verify-bpf: bpf
	@echo "Verifying BPF programs load..."
	@for obj in $(BPF_OBJECTS); do \
		echo "Checking $$obj..."; \
		$(BPFTOOL) prog load $$obj /sys/fs/bpf/kernelseal_test 2>&1 || true; \
		rm -f /sys/fs/bpf/kernelseal_test 2>/dev/null || true; \
	done

.PHONY: run
run: all
	@echo "Running KernelSeal..."
	sudo $(BUILD_DIR)/$(BINARY) -config examples/config.yaml \
		-exec-monitor $(BPF_DIR)/exec_monitor.bpf.o \
		-lsm $(BPF_DIR)/lsm_file_protect.bpf.o

.PHONY: help
help:
	@echo "KernelSeal Build System"
	@echo ""
	@echo "Build:"
	@echo "  all              - vmlinux.h, BPF objects, both binaries"
	@echo "  bpf              - Compile BPF programs"
	@echo "  build            - Build both Go binaries"
	@echo "  build-agent      - Build the kernelseal agent only"
	@echo "  build-shim       - Build the kernelseal-exec shim only"
	@echo "  docker           - Build the container image"
	@echo "  docker-dev       - Build BPF objects in a container, then the image"
	@echo ""
	@echo "Verify:"
	@echo "  verify           - fmt, vet, ABI check, unit and delivery tests"
	@echo "  test             - Unit tests"
	@echo "  test-delivery    - Secret delivery tests (no privileges needed)"
	@echo "  test-integration - Full suite including LSM enforcement (needs root)"
	@echo "  abi-check        - Check the BPF/Go struct ABI"
	@echo "  lint             - Run golangci-lint"
	@echo ""
	@echo "Other:"
	@echo "  clean            - Remove build artifacts"
	@echo "  clean-all        - Also remove generated vmlinux.h"
	@echo "  install-deps     - Install build dependencies"
	@echo ""
	@echo "Variables: VERSION=$(VERSION) GOARCH=$(GOARCH)"
