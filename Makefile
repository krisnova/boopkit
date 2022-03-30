TARGET := enohonk

#SRC_DIR = $(shell realpath .)
#LIBBPF_DIR = $(SRC_DIR)/../libbpf/src/

CFLAGS ?= -I/usr/local/include
#CFLAGS ?= -I$(LIBBPF_DIR)/root/usr/include/

LDFLAGS ?= ""
#LDFLAGS ?= -L$(LIBBPF_DIR)

#LIBS = ""
LIBS = -lbpf -lelf

all: $(TARGET) enohonk.o

.PHONY: clean

clean:
	rm -f $(TARGET)
	rm -f enohonk.o
	rm -f enohonk.ll

$(TARGET): %: clean probe.c Makefile
	clang $(CFLAGS) $(LDFLAGS) -o $(TARGET) loader.c -Wl, $(LIBS)

enohonk.o: probe.c
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g probe.c
	llc -march=bpf -filetype=obj -o enohonk.o probe.ll

