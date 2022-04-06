TARGET := boopkit

CFLAGS ?= -I/usr/local/include
LDFLAGS ?= ""
LIBS = -lbpf -lelf

all: $(TARGET) boopkit.o

.PHONY: clean
clean:
	rm -f $(TARGET)
	rm -f boopkit.o
	rm -f probe.ll

.PHONY: remote
remote: remote/trigger.c
	cd remote && make


$(TARGET): %: clean probe.c Makefile
	clang $(CFLAGS) $(LDFLAGS) -o $(TARGET) loader.c -Wl, $(LIBS)

boopkit.o: probe.c
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g probe.c
	llc -march=bpf -filetype=obj -o boopkit.o probe.ll

