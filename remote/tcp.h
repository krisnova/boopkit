// SPDX-License-Identifier: GPL-2.0

#ifndef ENOHONK_TCP_H
#define ENOHONK_TCP_H

struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

void create_data_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char* data, int data_len, char** out_packet, int* out_packet_len);
void create_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** out_packet, int* out_packet_len);
void create_ack_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len);
void create_ack_rst_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len);
void create_rst_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len);
void create_bad_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** out_packet, int* out_packet_len);
int receive_from(int sock, char* buffer, size_t buffer_length, struct sockaddr_in *dst);
void read_seq_and_ack(const char* packet, uint32_t* seq, uint32_t* ack);



#define DATAGRAM_LEN 4096
#define OPT_SIZE 20

#endif // ENOHONK_TCP_H
