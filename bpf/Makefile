# Makefile for compiling Sentinel-RS eBPF kernel bytecode
CLANG ?= clang-19
LLVM_STRIP ?= llvm-strip-19
BPFTOOL ?= /usr/sbin/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
          -I/usr/include/$(shell uname -m)-linux-gnu \
          -I/usr/include \
          -I. \
          -Wall -Werror

all: vmlinux.h sentinel.bpf.o

vmlinux.h:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h from running kernel BTF..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

sentinel.bpf.o: sentinel.bpf.c vmlinux.h sentinel_types.h
	@echo "Compiling eBPF object sentinel.bpf.o..."
	$(CLANG) $(CFLAGS) -c sentinel.bpf.c -o sentinel.bpf.o
	@echo "Validating BTF in sentinel.bpf.o..."
	@$(BPFTOOL) btf dump file sentinel.bpf.o > /dev/null
	@echo "eBPF object sentinel.bpf.o built successfully."

clean:
	rm -f sentinel.bpf.o vmlinux.h

.PHONY: all clean
