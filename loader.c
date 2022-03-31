
#include <stdio.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

// enum bpf_prog_type {
//	BPF_PROG_TYPE_UNSPEC,
//	BPF_PROG_TYPE_SOCKET_FILTER,
//	BPF_PROG_TYPE_KPROBE,
//	BPF_PROG_TYPE_SCHED_CLS,
//	BPF_PROG_TYPE_SCHED_ACT,
//	BPF_PROG_TYPE_TRACEPOINT,
//	BPF_PROG_TYPE_XDP,
//	BPF_PROG_TYPE_PERF_EVENT,
//	BPF_PROG_TYPE_CGROUP_SKB,
//	BPF_PROG_TYPE_CGROUP_SOCK,
//	BPF_PROG_TYPE_LWT_IN,
//	BPF_PROG_TYPE_LWT_OUT,
//	BPF_PROG_TYPE_LWT_XMIT,
//	BPF_PROG_TYPE_SOCK_OPS,
//	BPF_PROG_TYPE_SK_SKB,
//	BPF_PROG_TYPE_CGROUP_DEVICE,
//	BPF_PROG_TYPE_SK_MSG,
//	BPF_PROG_TYPE_RAW_TRACEPOINT,
//	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
//	BPF_PROG_TYPE_LWT_SEG6LOCAL,
//	BPF_PROG_TYPE_LIRC_MODE2,
//	BPF_PROG_TYPE_SK_REUSEPORT,
//	BPF_PROG_TYPE_FLOW_DISSECTOR,
//	BPF_PROG_TYPE_CGROUP_SYSCTL,
//	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
//	BPF_PROG_TYPE_CGROUP_SOCKOPT,
//	BPF_PROG_TYPE_TRACING,
//	BPF_PROG_TYPE_STRUCT_OPS,
//	BPF_PROG_TYPE_EXT,
//	BPF_PROG_TYPE_LSM,
//	BPF_PROG_TYPE_SK_LOOKUP,
//	BPF_PROG_TYPE_SYSCALL, /* a program that can execute syscalls */
//};

int main(int argc, char **argv) {
    char path[PATH_MAX] = "enohonk.o";
    int loaded;
    struct bpf_object *obj;

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
    printf("eBPF Loaded Success: %d\n", loaded);
    printf("Started eBPF probe: %s\n", path);

    // Name
    const char *objname = bpf_object__name(obj);
    printf("eBPF Object name: %s\n", objname);

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


    sleep(100);



    return 0;
}