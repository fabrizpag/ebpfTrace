BIN="simple"

all:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@clang -g -O3 -target bpf -D__TARGET_RACH_x86_64 -c $(BIN).bpf.c -o $(BIN).bpf.o
	@bpftool gen skeleton $(BIN).bpf.o name $(BIN) > $(BIN).skel.h
	@clang $(BIN).c -I/usr/include/bpf -lbpf -lelf  -o $(BIN)

.PHONY: clean
clean:
	@rm -rf *.o *.skel.h vmlinux.h $(BIN)
