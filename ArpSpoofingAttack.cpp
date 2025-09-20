#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#define DESTINATION_IP "192.168.128.2"
#define SOURCE_MAC "92:5d:e7:75:c4:8e"

struct ethernet_header {
    uint8_t dest_mac[ETH_ALEN];
    uint8_t source_mac[ETH_ALEN];
    uint16_t ethertype;
};

unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

int main() {
    int sockfd;
    struct sockaddr_ll socket_address;
    struct ethernet_header ethHeader;
    struct ip ipHeader;
    struct icmp icmpHeader;
    char packet[4096];

    /* Create raw socket */
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation error");
        return 1;
    }

    /* Set destination address */
    struct sockaddr_ll interface_address;
    memset(&interface_address, 0, sizeof(struct sockaddr_ll));
    interface_address.sll_family = AF_PACKET;
    interface_address.sll_protocol = htons(ETH_P_ALL);
    interface_address.sll_ifindex = if_nametoindex("eth0"); /* Replace with your network interface name */

    /* Prepare Ethernet header */
    memset(&ethHeader, 0, sizeof(struct ethernet_header));
    sscanf(SOURCE_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &ethHeader.source_mac[0], &ethHeader.source_mac[1],
           &ethHeader.source_mac[2], &ethHeader.source_mac[3],
           &ethHeader.source_mac[4], &ethHeader.source_mac[5]);
    memcpy(&ethHeader.dest_mac, ether_aton("ff:ff:ff:ff:ff:ff"), ETH_ALEN); /* Destination MAC set to broadcast address */
    ethHeader.ethertype = htons(ETH_P_IP);

    /* Prepare IP header */
    memset(&ipHeader, 0, sizeof(struct ip));
    ipHeader.ip_hl = 5;
    ipHeader.ip_v = 4;
    ipHeader.ip_ttl = 64;
    ipHeader.ip_p = IPPROTO_ICMP;
    ipHeader.ip_src.s_addr = inet_addr("0.0.0.0"); /* Use the default source IP address */
    ipHeader.ip_dst.s_addr = inet_addr(DESTINATION_IP);

    /* Prepare ICMP header */
    memset(&icmpHeader, 0, sizeof(struct icmp));
    icmpHeader.icmp_type = ICMP_ECHO;
    icmpHeader.icmp_code = 0;
    icmpHeader.icmp_id = htons(getpid() & 0xFFFF);
    icmpHeader.icmp_seq = htons(1);
    icmpHeader.icmp_cksum = 0;
    icmpHeader.icmp_cksum = in_cksum((unsigned short *)&icmpHeader, sizeof(struct icmp));

    /* Construct the packet */
    memcpy(packet, &ethHeader, sizeof(struct ethernet_header));
    memcpy(packet + sizeof(struct ethernet_header), &ipHeader, sizeof(struct ip));
    memcpy(packet + sizeof(struct ethernet_header) + sizeof(struct ip), &icmpHeader, sizeof(struct icmp));

    /* Send the packet */
    if (sendto(sockfd, packet, sizeof(struct ethernet_header) + sizeof(struct ip) + sizeof(struct icmp), 0,
               (struct sockaddr *)&interface_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("Packet send error");
        return 1;
    }

    printf("Packet sent successfully!\n");
    close(sockfd);
    return 0;
}
