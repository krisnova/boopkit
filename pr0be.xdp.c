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
// [boops.c]
//
// This file is used to build the eBPF probes that
// will respond to various "boops" from a boop.
//
// This file has one job: get booped and pass __u8 saddr[4]
// to userspace!
//
// clang-format off
#include "vmlinux.h"
// clang-format on
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#include "boopkit.h"

static inline __u64 ether_addr_to_u64(const __u8 *addr){
  __u64 u = 0;
  int i;
  int ETH_ALEN = 6; // Taken from Linux headers <linux/if_ether.h>
  for (i = ETH_ALEN - 1; i >= 0; i--)
    u = u << 8 | addr[i];
  return u;
}


SEC("xdp")
int  xdp_boops(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  __u64 offset = sizeof(*eth);

  if ((void *)eth + offset > data_end)
    return 0;

  bpf_printk("src: %llu, dst: %llu, proto: %u\n",
             ether_addr_to_u64(eth->h_source),
             ether_addr_to_u64(eth->h_dest),
             bpf_ntohs(eth->h_proto));

  return XDP_PASS;
}

// SPDX-License-Identifier: GPL-2.0
// The eBPF probe is dual-licensed with GPL because Linux is a fucking shit
// show.
char LICENSE[] SEC("license") = "GPL";