// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "tcp.h"

int main(int argc, char** argv){
    srand(time(NULL));
    if (argc != 4){
        printf("Invalid parameters.\n");
        printf("USAGE %s <source-ip> <target-ip> <port>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1){
        printf("socket creation failed\n");
        return 1;
    }

    // Destination
    struct sockaddr_in daddr;
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(atoi(argv[3]));
    if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1){
        printf("destination IP configuration failed\n");
        return 1;
    }

    // Source
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(rand() % 65535); // random client port
    if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1)
    {
        printf("source IP configuration failed\n");
        return 1;
    }

    // Socket connection
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1){
        printf("setsockopt(IP_HDRINCL, 1) failed\n");
        return 1;
    }

    char* packet;
    int packet_len;
    create_bad_syn_packet(&saddr, &daddr, &packet, &packet_len);
    int sent;
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1){
        printf("Connection refused.\n");
    }
    printf("SYN      [bad checksum] -> %d bytes to   %s:%s\n", sent, argv[2], argv[3]);


    create_syn_packet(&saddr, &daddr, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1){
      printf("Connection refused.\n");
    }
    printf("SYN      [    okay    ] -> %d bytes to %s:%s\n", sent, argv[2], argv[3]);


    char recvbuf[DATAGRAM_LEN];
    int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
    if (received <= 0){
      printf("Unable to receive SYN-ACK\n");
      return 0;
    }
    printf("SYN-ACK  [    okay    ] <- %d bytes from %s\n", received, argv[2]);


    // Read sequence numbers for SYN-ACK
    uint32_t seq_num, ack_num;
    read_seq_and_ack(recvbuf, &seq_num, &ack_num);
    int new_seq_num = seq_num + 1;

    create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1){
      printf("Connection refused.\n");
    }
    printf("ACK      [    okay    ] -> %d bytes to %s:%s\n", sent, argv[2], argv[3]);

    
    create_rst_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1){
      printf("Connection refused.\n");
    }
    printf("RST      [    okay    ] -> %d bytes to %s:%s\n", sent, argv[2], argv[3]);




    // ------------
    close(sock);
    return 0;
    // ------------
}