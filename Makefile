TARGET  := boopkit
CFLAGS  ?= -I/usr/local/include
LDFLAGS ?= ""
LIBS     = -lbpf -lelf
STYLE    = Google

all: $(TARGET) boopkit.o skeleton

.PHONY: clean
clean:
	rm -f $(TARGET)
	rm -f boopkit.o
	rm -f boops.ll
	rm -f probe.skel.h

.PHONY: remote
remote: remote/trigger.c
	cd remote && make

skeleton:
	#bpftool gen skeleton boopkit.o -p > probe.skel.h


format:
	clang-format -i -style=$(STYLE) *.c *.h
	clang-format -i -style=$(STYLE) remote/*.c remote/*.h

$(TARGET): %: clean boops.c Makefile
	clang $(CFLAGS) $(LDFLAGS) -o $(TARGET) loader.c -Wl, $(LIBS)

boopkit.o: boops.c
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g boops.c
	llc -march=bpf -filetype=obj -o boop.pr0be.o boops.ll

safe.o: safe.c
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Werror \
	    -O2 -emit-llvm -c -g boops.c
	llc -march=bpf -filetype=obj -o safe.pr0be.o safe.ll