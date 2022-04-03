
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "string.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 64);
} events SEC(".maps");

struct tcp_bad_csum_args_t {
    __u64 _unused;
    __u8 saddr[4];
    __u8 daddr[4];
};

// name: tcp_bad_csum
// ID: 1363
// format:
// field:unsigned short common_type;       offset:0;       size:2; signed:0;
// field:unsigned char common_flags;       offset:2;       size:1; signed:0;
// field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
// field:int common_pid;   offset:4;       size:4; signed:1;
//
// field:const void * skbaddr;     offset:8;       size:8; signed:0;
// field:__u8 saddr[sizeof(struct sockaddr_in6)];  offset:16;      size:28;   signed:0;
// field:__u8 daddr[sizeof(struct sockaddr_in6)];  offset:44;      size:28;   signed:0;
//
// print fmt: "src=%pISpc dest=%pISpc", REC->saddr, REC->daddr
SEC("tracepoint/tcp/tcp_bad_csum")
int tcp_bad_csum(struct tcp_bad_csum_args_t  *args){
    // Only element on the eBPF map is going to be our "source address"
    int saddrkey = 1;
    int val = 1;
    bpf_map_update_elem(&events, &saddrkey, &val, 1);
    return 0;
}

// The following code is GPL licensed
char LICENSE[] SEC("license") = "GPL";
// The prior code is GPL licensed