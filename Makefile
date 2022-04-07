TARGET  := boopkit
CFLAGS  ?= -I/usr/local/include
LDFLAGS ?= ""
LIBS     = -lbpf -lelf
STYLE    = Google

all: boopkit.o safe.o skeleton build

.PHONY: clean
clean:
	rm -f $(TARGET)
	rm -f *.o
	rm -f *.ll
	rm -f pr0be.skel.h

.PHONY: remote
remote: remote/trigger.c
	cd remote && make

skeleton:
	bpftool gen skeleton pr0be.safe.o -p > pr0be.skel.h

format:
	clang-format -i -style=$(STYLE) *.c *.h
	clang-format -i -style=$(STYLE) remote/*.c remote/*.h

build:
	clang $(CFLAGS) $(LDFLAGS) -o $(TARGET) boopkit.c -Wl, $(LIBS)

boopkit.o: pr0be.boop.c
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g pr0be.boop.c
	llc -march=bpf -filetype=obj -o pr0be.boop.o pr0be.boop.ll

safe.o: pr0be.safe.c
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g pr0be.safe.c
	llc -march=bpf -filetype=obj -o pr0be.safe.o pr0be.safe.ll

