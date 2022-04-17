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

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>

// clang-format off
#include "packets.h"
// clang-format on

unsigned short csum(const char *buf, unsigned size) {
  unsigned sum = 0, i;
  for (i = 0; i < size - 1; i += 2) {
    unsigned short word16 = *(unsigned short *)&buf[i];
    sum += word16;
  }
  if (size & 1) {
    unsigned short word16 = (unsigned char)buf[i];
    sum += word16;
  }
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return ~sum;
}

void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       char **out_packet, int *out_packet_len) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;             // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48);  // mss value
  memcpy(datagram + 42, &mss, sizeof(int16_t));
  // ---- enable SACK ----
  datagram[44] = 0x04;
  datagram[45] = 0x02;
  // do the same for the pseudo header
  pseudogram[32] = 0x02;
  pseudogram[33] = 0x04;
  memcpy(pseudogram + 34, &mss, sizeof(int16_t));
  pseudogram[36] = 0x04;
  pseudogram[37] = 0x02;

  tcph->check = csum((const char *)pseudogram, psize);
  iph->check = csum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       int32_t seq, int32_t ack_seq, char **out_packet,
                       int *out_packet_len) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;             // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = csum((const char *)pseudogram, psize);
  iph->check = csum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void create_ack_rst_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                           int32_t seq, int32_t ack_seq, char **out_packet,
                           int *out_packet_len) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 1;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;             // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = csum((const char *)pseudogram, psize);
  iph->check = csum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void create_rst_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       char **out_packet, int *out_packet_len) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 1;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;             // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = csum((const char *)pseudogram, psize);
  iph->check = csum((const char *)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

// create_bad_syn_packet_payload will build a TCP SYN packet with an arbitrary
// payload attached to the SYN packet.
void create_bad_syn_packet_payload(struct sockaddr_in *src,
                                   struct sockaddr_in *dst, char **out_packet,
                                   int *out_packet_len, char *payload) {
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr *)datagram;
  struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535);  // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;  // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10;  // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;                       // correct calculation follows later
  tcph->window = htons(5840);  // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char *pseudogram = malloc(psize);
  memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
         sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48);  // mss value
  memcpy(datagram + 42, &mss, sizeof(int16_t));
  // ---- enable SACK ----
  datagram[44] = 0x04;
  datagram[45] = 0x02;

  // [46] begin data transmission for datagram
  // Append the payload to the datagram
  int offset = 46;
  for (int i = 0; i < strlen(payload); i++) {
    datagram[offset + i] = payload[i];
  }

  // do the same for the pseudo header
  pseudogram[32] = 0x02;
  pseudogram[33] = 0x04;
  memcpy(pseudogram + 34, &mss, sizeof(int16_t));
  pseudogram[36] = 0x04;
  pseudogram[37] = 0x02;

  // 38 begin data transmission for pseudogram
  offset = 38;
  for (int i = 0; i < strlen(payload); i++) {
    datagram[offset + i] = payload[i];
  }

  // create a bad (malformed) SYN packet without a checksum.
  // tcph->check = csum((const char*)pseudogram, psize);
  // iph->check = csum((const char*)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void read_seq_and_ack(const char *packet, uint32_t *seq, uint32_t *ack) {
  // read sequence number
  uint32_t seq_num;
  memcpy(&seq_num, packet + 24, 4);
  // read acknowledgement number
  uint32_t ack_num;
  memcpy(&ack_num, packet + 28, 4);
  // convert network to host byte order
  *seq = ntohl(seq_num);
  *ack = ntohl(ack_num);
}

int receive_from(int sock, char *buffer, size_t buffer_length,
                 struct sockaddr_in *dst) {
  unsigned short dst_port;
  int received;
  do {
    received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
    if (received <= 0) break;
    memcpy(&dst_port, buffer + 22, sizeof(dst_port));
  } while (dst_port != dst->sin_port);
  return received;
}
