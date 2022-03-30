
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct tcp_probe_args_t {
    __u64 _unused;
};

struct tcp_probe_data_t {
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


//name: tcp_probe
//ID: 1364
//format:
//        field:unsigned short common_type;       offset:0;       size:2; signed:0;
//        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//        field:int common_pid;   offset:4;       size:4; signed:1;
//
//        field:__u8 saddr[sizeof(struct sockaddr_in6)];  offset:8;       size:28;   signed:0;
//        field:__u8 daddr[sizeof(struct sockaddr_in6)];  offset:36;      size:28;   signed:0;
//        field:__u16 sport;      offset:64;      size:2; signed:0;
//        field:__u16 dport;      offset:66;      size:2; signed:0;
//        field:__u16 family;     offset:68;      size:2; signed:0;
//        field:__u32 mark;       offset:72;      size:4; signed:0;
//        field:__u16 data_len;   offset:76;      size:2; signed:0;
//        field:__u32 snd_nxt;    offset:80;      size:4; signed:0;
//        field:__u32 snd_una;    offset:84;      size:4; signed:0;
//        field:__u32 snd_cwnd;   offset:88;      size:4; signed:0;
//        field:__u32 ssthresh;   offset:92;      size:4; signed:0;
//        field:__u32 snd_wnd;    offset:96;      size:4; signed:0;
//        field:__u32 srtt;       offset:100;     size:4; signed:0;
//        field:__u32 rcv_wnd;    offset:104;     size:4; signed:0;
//        field:__u64 sock_cookie;        offset:112;     size:8; signed:0;
//
//print fmt: "family=%s src=%pISpc dest=%pISpc mark=%#x data_len=%d snd_nxt=%#x snd_una=%#x snd_cwnd=%u ssthresh=%u snd_wnd=%u srtt=%u rcv_wnd=%u sock_cookie=%llx", __print_symbolic(REC->family, { 2, "AF_INET" }, { 10, "AF_INET6" }), REC->saddr, REC->daddr, REC->mark, REC->data_len, REC->snd_nxt, REC->snd_una, REC->snd_cwnd, REC->ssthresh, REC->snd_wnd, REC->srtt, REC->rcv_wnd, REC->sock_cookie
SEC("tracepoint/tcp/tcp_probe")
int tcp_probe(struct tcp_probe_args_t  *args){
    struct tcp_probe_data_t data = {};

//    data.oldstate = args->oldstate;
//    data.newstate = args->newstate;
//    data.sport = args->sport;
//    data.dport = args->dport;
//    data.family = args->family;
//    data.protocol = args->protocol;
//    memcpy(data.saddr, args->saddr, sizeof(args->saddr));
//    memcpy(data.daddr, args->daddr, sizeof(args->daddr));
//    memcpy(data.saddr_v6, args->saddr_v6, sizeof(args->saddr_v6));
//    memcpy(data.daddr_v6, args->daddr_v6, sizeof(args->daddr_v6));
//

    // Send out on the perf event map
    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

//    if (DEBUG) bpf_printk("---tracepoint/sock/inet_sock_set_state---");
    return 0;
}


char LICENSE[] SEC("license") = "GPL";