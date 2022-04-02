
#include <linux/bpf.h>
#include <unistd.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct tcp_retransmit_synack_args_t {
    __u64 _unused;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct tcp_retransmit_synack_data_t {
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

// name: tcp_retransmit_synack
//ID: 1365
//format:
//        field:unsigned short common_type;       offset:0;       size:2; signed:0;
//        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//        field:int common_pid;   offset:4;       size:4; signed:1;
//
//        field:const void * skaddr;      offset:8;       size:8; signed:0;
//        field:const void * req; offset:16;      size:8; signed:0;
//        field:__u16 sport;      offset:24;      size:2; signed:0;
//        field:__u16 dport;      offset:26;      size:2; signed:0;
//        field:__u16 family;     offset:28;      size:2; signed:0;
//        field:__u8 saddr[4];    offset:30;      size:4; signed:0;
//        field:__u8 daddr[4];    offset:34;      size:4; signed:0;
//        field:__u8 saddr_v6[16];        offset:38;      size:16;        signed:0;
//        field:__u8 daddr_v6[16];        offset:54;      size:16;        signed:0;
//
//print fmt: "family=%s sport=%hu dport=%hu saddr=%pI4 daddr=%pI4 saddrv6=%pI6c daddrv6=%pI6c", __print_symbolic(REC->family, { 2, "AF_INET" }, { 10, "AF_INET6" }), REC->sport, REC->dport, REC->saddr, REC->daddr, REC->saddr_v6, REC->daddr_v6
SEC("tracepoint/tcp/tcp_retransmit_synack")
int tcp_retransmit_synack(struct tcp_retransmit_synack_args_t  *args){
    struct tcp_retransmit_synack_data_t data = {};
    bpf_printk("src: %pI4\n", args->saddr);
    bpf_printk("dst: %pI4\n", args->daddr);
    bpf_printk("* HACKED THE PLANET *");
    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

// The following code is GPL licensed
char LICENSE[] SEC("license") = "GPL";
// The prior code is GPL licensed