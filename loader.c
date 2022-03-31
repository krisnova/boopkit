
#include <stdio.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char path[PATH_MAX] = "enohonk.o";
    int loaded;
    struct bpf_object *obj;
    printf("-----------------------------------------------\n");
    printf("Loading eBPF Probe: %s\n", path);
    obj = bpf_object__open(path);
    if (!obj) {
        printf("Unable to load eBPF object: %s\n", path);
        return 1;
    }

    loaded = bpf_object__load(obj);
    if (loaded < 0) {
        printf("Unable to start eBPF probe: %s\n", path);
        return 1;
    }
    printf("eBPF Probe Loaded: %s\n", path);

    // Name
    const char *objname = bpf_object__name(obj);
    printf("eBPF Object Name: %s\n", objname);

    struct bpf_program *program = NULL;

    // TODO Iterate over programs if we end up adding more
    program = bpf_object__next_program(obj, NULL);
    printf("eBPF Program Address: %p\n", program);

    // Program Name
    const char *progname = bpf_program__name(program);
    printf("eBPF Program Name: %s\n", progname);

    // Program Section Name
    const char *progsecname = bpf_program__section_name(program);
    printf("eBPF Program Section Name: %s\n", progsecname);


    struct bpf_link *link = bpf_program__attach(program);
    if (!link) {
        printf("Unable to link eBPF program: %s\n", progname);
        return 2;
    }

    printf("eBPF Program Linked!\n");
    printf("Logs: cat /sys/kernel/tracing/trace_pipe\n");
    printf("-----------------------------------------------\n");

    // TODO We probably want to "pin" the eBPF probe so that it will persist
    while(1){}

    return 0;
}