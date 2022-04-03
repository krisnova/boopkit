// Copyright © 2022 Kris Nóva <kris@nivenly.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
// ████╗  ██║██╔═████╗██║   ██║██╔══██╗
// ██╔██╗ ██║██║██╔██║██║   ██║███████║
// ██║╚██╗██║████╔╝██║╚██╗ ██╔╝██╔══██║
// ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
// ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
//

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include <netinet/in.h>
#include "proto.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, int);
  __type(value, struct tcp_return);
} events SEC(".maps");

struct tcp_bad_csum_args_t {

    // Here be dragons
    //
    // The padding here is to offset the embedded IPv4 address
    // inside the IPv6 address block. We had to manually buffer
    // the struct to get the memory allocation correct for saddr.
    //
    // We can use various paddings to pull the IPv4 out of the
    // fields in memory. Not how the size of sizeof(struct sockaddr_in6)
    // in the eBPF format file!
    //
    //
    __u8 headerpadding[16];
    __u8 pad1[4];
    __u8 saddr[4];
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
    //bpf_printk("tcp_bad_csum saddr=%pI4", args->saddr);
    int saddrkey = 1;
    struct tcp_return ret;
    memcpy(ret.saddr, args->saddr, sizeof(args->saddr));
    bpf_map_update_elem(&events, &saddrkey, &ret, 1);
    return 0;
}

// SPDX-License-Identifier: GPL-2.0
// The eBPF probe is dual-licensed with GPL because Linux is a fucking shit show.
char LICENSE[] SEC("license") = "GPL";
