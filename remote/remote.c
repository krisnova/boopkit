#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "tcp.h"

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
    printf("sequence number: %lu\n", (unsigned long)*seq);
    printf("acknowledgement number: %lu\n", (unsigned long)*seq);
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
    printf("received bytes: %d\n", received);
    printf("destination port: %d\n", ntohs(dst->sin_port));
    return received;
}

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        printf("invalid parameters.\n");
        printf("USAGE %s <source-ip> <target-ip> <port>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1)
    {
        printf("socket creation failed\n");
        return 1;
    }

    // destination IP address configuration
    struct sockaddr_in daddr;
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(atoi(argv[3]));
    if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1)
    {
        printf("destination IP configuration failed\n");
        return 1;
    }

    // source IP address configuration
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(rand() % 65535); // random client port
    if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1)
    {
        printf("source IP configuration failed\n");
        return 1;
    }

    printf("selected source port number: %d\n", ntohs(saddr.sin_port));
    printf("saddr: %s\n", argv[1]);
    printf("daddr: %s\n", argv[2]);

    // tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
    {
        printf("setsockopt(IP_HDRINCL, 1) failed\n");
        return 1;
    }

    // send SYN
    char* packet;
    int packet_len;
    create_syn_packet(&saddr, &daddr, &packet, &packet_len);

    int sent;
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
    {
        printf("sendto() failed\n");
    }
    else
    {
        printf("successfully sent %d bytes SYN!\n", sent);
    }

    // receive SYN-ACK
    char recvbuf[DATAGRAM_LEN];
    int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
    if (received <= 0)
    {
        printf("receive_from() failed\n");
    }
    else
    {
        printf("successfully received %d bytes SYN-ACK!\n", received);
    }

    // read sequence number to acknowledge in next packet
    uint32_t seq_num, ack_num;
    read_seq_and_ack(recvbuf, &seq_num, &ack_num);
    int new_seq_num = seq_num + 1;

    // send ACK
    // previous seq number is used as ack number and vica vera
    create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
    {
        printf("sendto() failed\n");
    }
    else
    {
        printf("successfully sent %d bytes ACK!\n", sent);
    }

    // send the malformed packet with the bad checksum
    create_bad_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
    if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
    {
      printf("sendto() failed\n");
    }
    else
    {
      printf("successfully sent %d bytes MALFORMED!\n", sent);
    }
    close(sock);
    printf("Closing socket...\n");
    return 0;
}