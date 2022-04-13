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
#define MAX_RCE_SIZE 128

struct encapsulated_tcp_boop {
  // saddr is the 4 byte minimum required to pass an
  // IP address over TCP
  __u8 saddrval[4];  // Saturn Valley

  // rce is an optional buffer to fill with a command if
  // a boop can encapsulate one.
  char rce[MAX_RCE_SIZE];
};

// VERSION is the semantic version of the program
#define VERSION "1.0.6"

// PORT for the boopkit TCP protocol for boopscript RCE
#define PORT 3535

// MAX_DENY_ADDRS is the maximum amount of address that can be denied.
#define MAX_DENY_ADDRS 1024

// MAX_PORT_STR is the port size for rport and lport
#define MAX_PORT_STR 32

// PROBE_BOOP is the eBPF probe to listen for boops
#define PROBE_BOOP "pr0be.boop.o"
#define PROBE_SAFE "pr0be.safe.o"

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

#endif  // BOOPKIT_BOOPKIT_H
