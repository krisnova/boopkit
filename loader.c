

#include <stdio.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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
    int loader_fd;
    struct bpf_object *loader_obj;
    if (bpf_prog_load(path, BPF_PROG_TYPE_TRACEPOINT, &loader_obj, &loader_fd) != 0){
        printf("Unable to load persistent eBPF probe: %s\n", path);
        return 1;
    }
    if (loader_fd < 1) {
        printf("Unable to start eBPF probe: %s\n", path);
        return 1;
    }
    printf("Started eBPF probe: %s\n", path);
    return 0;
}