// SPDX-License-Identifier: GPL-2.0

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include "tcp.h"

unsigned short checksum(const char *buf, unsigned size)
{
  unsigned sum = 0, i;

  /* Accumulate checksum */
  for (i = 0; i < size - 1; i += 2)
  {
    unsigned short word16 = *(unsigned short *) &buf[i];
    sum += word16;
  }

  /* Handle odd-sized case */
  if (size & 1)
  {
    unsigned short word16 = (unsigned char) buf[i];
    sum += word16;
  }

  /* Fold to get the ones-complement result */
  while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

  /* Invert to get the negative in ones-complement arithmetic */
  return ~sum;
}

void create_data_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char* data, int data_len, char** out_packet, int* out_packet_len)
{
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr*)datagram;
  struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // set payload
  char* payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  memcpy(payload, data, data_len);

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 1;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0; // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + data_len);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
  // fill pseudo packet
  char* pseudogram = malloc(psize);
  memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE + data_len);

  tcph->check = checksum((const char*)pseudogram, psize);
  iph->check = checksum((const char*)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void create_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** out_packet, int* out_packet_len)
{
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr*)datagram;
  struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0; // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char* pseudogram = malloc(psize);
  memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48); // mss value
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

  tcph->check = checksum((const char*)pseudogram, psize);
  iph->check = checksum((const char*)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}


void create_ack_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len)
{
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr*)datagram;
  struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0; // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char* pseudogram = malloc(psize);
  memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = checksum((const char*)pseudogram, psize);
  iph->check = checksum((const char*)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void create_ack_rst_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len)
{
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr*)datagram;
  struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 1;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0; // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char* pseudogram = malloc(psize);
  memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = checksum((const char*)pseudogram, psize);
  iph->check = checksum((const char*)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}

void create_rst_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len)
{
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr*)datagram;
  struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 1;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0; // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char* pseudogram = malloc(psize);
  memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

  tcph->check = checksum((const char*)pseudogram, psize);
  iph->check = checksum((const char*)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}



void create_bad_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** out_packet, int* out_packet_len)
{
  char *datagram = calloc(DATAGRAM_LEN, sizeof(char));
  struct iphdr *iph = (struct iphdr*)datagram;
  struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
  struct pseudo_header psh;

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  iph->id = htonl(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0; // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP pseudo header for checksum calculation
  psh.source_address = src->sin_addr.s_addr;
  psh.dest_address = dst->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
  // fill pseudo packet
  char* pseudogram = malloc(psize);
  memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48); // mss value
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

  // create a bad (malformed) SYN packet without a checksum.
  //tcph->check = checksum((const char*)pseudogram, psize);
  //iph->check = checksum((const char*)datagram, iph->tot_len);

  *out_packet = datagram;
  *out_packet_len = iph->tot_len;
  free(pseudogram);
}


void read_seq_and_ack(const char* packet, uint32_t* seq, uint32_t* ack)
{
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

int receive_from(int sock, char* buffer, size_t buffer_length, struct sockaddr_in *dst)
{
    unsigned short dst_port;
    int received;
    do
    {
        received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
        if (received < 0)
            break;
        memcpy(&dst_port, buffer + 22, sizeof(dst_port));
    }
    while (dst_port != dst->sin_port);
    return received;
}
