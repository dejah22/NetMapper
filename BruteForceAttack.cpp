#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define SOURCE_PORT 12345
#define DESTINATION_IP "192.168.128.2"
#define DESTINATION_PORT 80

int main() {
    int sockfd;
    struct sockaddr_in destAddr;
    char packet[4096];
    struct iphdr *ipHeader = (struct iphdr *) packet;
    struct tcphdr *tcpHeader = (struct tcphdr *) (packet + sizeof(struct ip));

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation error");
        return 1;
    }

    // Set destination address
    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // IP header
    ipHeader->ihl = 5;
    ipHeader->version = 4;
    ipHeader->ttl = 64;
    ipHeader->protocol = IPPROTO_TCP;
    ipHeader->saddr = inet_addr("0.0.0.0"); // Use the default source IP address
    ipHeader->daddr = destAddr.sin_addr.s_addr;

    // TCP header
    tcpHeader->source = htons(SOURCE_PORT);
    tcpHeader->dest = htons(DESTINATION_PORT);
    tcpHeader->seq = htonl(1); // Set the initial sequence number
    tcpHeader->ack_seq = 0;
    tcpHeader->doff = 5; // TCP header length
    tcpHeader->syn = 1; // SYN flag
    tcpHeader->window = htons(65535); // Maximum window size

    // Calculate TCP checksum
    tcpHeader->check = 0;
    uint16_t tcpLength = sizeof(struct tcphdr);
    uint32_t pseudoHeaderChecksum = (ipHeader->saddr & 0xFFFF) +
                                    (ipHeader->saddr >> 16) +
                                    (ipHeader->daddr & 0xFFFF) +
                                    (ipHeader->daddr >> 16) +
                                    htons(ipHeader->protocol) +
                                    htons(tcpLength);

    uint16_t *pseudoHeader = (uint16_t *) malloc(sizeof(uint16_t) * (tcpLength + 12));
    memcpy((char *) pseudoHeader + 12, tcpHeader, tcpLength);
    tcpHeader->check = in_cksum((uint16_t *) pseudoHeader, tcpLength + 12);
    free(pseudoHeader);

    // Send the packet
    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *) &destAddr, sizeof(destAddr)) < 0) {
        perror("Packet send error");
        return 1;
    }

    printf("Packet sent successfully!\n");
    close(sockfd);
    return 0;
}

uint16_t in_cksum(uint16_t *addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}
