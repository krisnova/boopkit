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
// clang-format off
#include "vmlinux.h"
// clang-format on
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>
#include <stdbool.h>

#include "boopkit.h"

#define min(x, y) ((x) < (y) ? x : y)

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, MAX_ENTRIES_CPU);
  __type(key, int);
  __type(value, __u32);
} xcap_perf_map SEC(".maps");


struct trace_configuration trace_cfg SEC(".data");

static inline void trace_to_perf_buffer(struct xdp_buff *xdp, bool fexit, int action){
  void *data_end = (void *)(long)xdp->data_end;
  void *data = (void *)(long)xdp->data;
  struct pkt_trace_metadata metadata;

  if (data >= data_end){
    return;
  }

  metadata.prog_index = trace_cfg.capture_prog_index;
  metadata.ifindex = xdp->rxq->dev->ifindex;
  metadata.rx_queue = xdp->rxq->queue_index;
  metadata.pkt_len = (__u16)(data_end - data);
  metadata.cap_len = min(metadata.pkt_len, trace_cfg.capture_snaplen);
  metadata.action = action;
  metadata.flags = 0;

  bpf_xdp_output(xdp, &xcap_perf_map,
                 ((__u64) metadata.cap_len << 32) |
                     BPF_F_CURRENT_CPU,
                 &metadata, sizeof(metadata));
}

SEC("fentry/func")
int BPF_PROG(trace_on_entry, struct xdp_buff *xdp){
  trace_to_perf_buffer(xdp, false, 0);
  return 0;
}

SEC("fexit/func")
int BPF_PROG(trace_on_exit, struct xdp_buff *xdp, int ret){
  trace_to_perf_buffer(xdp, true, ret);
  return 0;
}


// XDP (Metadata only)
SEC("xdp")
int  xdp_xcap(struct xdp_md *xdp){
  void *data_end = (void *)(long)xdp->data_end;
  void *data = (void *)(long)xdp->data;
  struct pkt_trace_metadata metadata;

  if (data >= data_end){
    return XDP_PASS;
  }


  metadata.prog_index = trace_cfg.capture_prog_index;
  metadata.ifindex = xdp->ingress_ifindex;
  metadata.rx_queue = xdp->rx_queue_index;
  metadata.pkt_len = (__u16)(data_end - data);
  metadata.cap_len = min(metadata.pkt_len, trace_cfg.capture_snaplen);
  metadata.action = 0;
  metadata.flags = 0;
  bpf_perf_event_output(xdp, &xcap_perf_map,
                        ((__u64) metadata.cap_len << 32) |
                            BPF_F_CURRENT_CPU,
                        &metadata, sizeof(metadata));

  // --------------------
  //	XDP_ABORTED = 0,
  //	XDP_DROP = 1,
  //	XDP_PASS = 2,
  //	XDP_TX = 3,
  //	XDP_REDIRECT = 4,
  return XDP_PASS;
  // --------------------
}



// SPDX-License-Identifier: GPL-2.0
// The eBPF probe is dual-licensed with GPL because Linux is a fucking shit
// show.
char LICENSE[] SEC("license") = "GPL";