/*
 * netscan.c
 * Discover active hosts (ICMP echo) on a /24-like network base and scan TCP ports
 *
 * Notes:
 *  - Requires root privileges to create raw ICMP socket.
 *  - Many hosts/firewalls drop ICMP — you may get false negatives.
 *  - Scanning 1..65535 sequentially is very slow; consider scanning a subset or using concurrency.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>      /* struct iphdr */
#include <netinet/ip_icmp.h> /* struct icmphdr */
#include <netdb.h>

#define PACKET_SIZE 64
#define MAX_ACTIVE_HOSTS 256
#define PORT_SCAN_TIMEOUT_SEC 1

/* Internet checksum for ICMP */
unsigned short calculate_checksum(unsigned short *addr, int len) {
    unsigned int sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)addr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* set socket non-blocking */
void set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        exit(EXIT_FAILURE);
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        exit(EXIT_FAILURE);
    }
}

/* Non-blocking TCP connect scan of ports 1..65535 on host (dotted decimal) */
void scan_ports(const char *host) {
    int port;
    struct sockaddr_in target;
    struct timeval timeout;
    fd_set writefds;

    printf("Scanning ports on %s (this may take a long time)...\n", host);

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    if (inet_pton(AF_INET, host, &target.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP for port scan: %s\n", host);
        return;
    }

    timeout.tv_sec = PORT_SCAN_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    for (port = 1; port <= 65535; ++port) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket()");
            return;
        }

        target.sin_port = htons(port);
        set_nonblocking(sockfd);

        if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) < 0) {
            if (errno != EINPROGRESS) {
                /* immediate failure */
                close(sockfd);
                continue;
            }

            FD_ZERO(&writefds);
            FD_SET(sockfd, &writefds);

            int sel = select(sockfd + 1, NULL, &writefds, NULL, &timeout);
            if (sel > 0 && FD_ISSET(sockfd, &writefds)) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0) {
                    if (so_error == 0) {
                        printf("Open port: %d\n", port);
                    }
                }
            }
        } else {
            /* immediate connect success (rare) */
            printf("Open port: %d\n", port);
        }

        close(sockfd);
    }
}

/* Send ICMP Echo (ping) to each IP in the /24 based on `network_base` and scan discovered hosts */
void scan_network(const char *network_base) {
    int raw_sock;
    struct sockaddr_in target;
    char icmp_packet[sizeof(struct icmphdr)];
    char recvbuf[PACKET_SIZE + 128];
    struct timeval timeout;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    char active_hosts[MAX_ACTIVE_HOSTS][INET_ADDRSTRLEN];
    int num_active = 0;

    /* Create raw ICMP socket */
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_sock < 0) {
        perror("socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
        exit(EXIT_FAILURE);
    }

    /* Set receive timeout */
    timeout.tv_sec = 1; /* 1 second */
    timeout.tv_usec = 0;
    if (setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;

    /* Build base copy of network_base (expecting form like "192.168.1.0" or "192.168.1") */
    char base_copy[INET_ADDRSTRLEN];
    strncpy(base_copy, network_base, sizeof(base_copy));
    base_copy[sizeof(base_copy)-1] = '\0';

    /* Remove last octet if present */
    char *last_dot = strrchr(base_copy, '.');
    if (last_dot) {
        *last_dot = '\0';
    }

    for (int i = 1; i <= 255; ++i) {
        char dst_ip[INET_ADDRSTRLEN];
        snprintf(dst_ip, sizeof(dst_ip), "%s.%d", base_copy, i);

        if (inet_pton(AF_INET, dst_ip, &target.sin_addr) != 1) {
            continue;
        }

        /* Prepare ICMP echo request (kernel will build the IP header) */
        memset(icmp_packet, 0, sizeof(icmp_packet));
        struct icmphdr *icmp_hdr = (struct icmphdr *)icmp_packet;
        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->un.echo.id = htons((unsigned short)(getpid() & 0xFFFF));
        icmp_hdr->un.echo.sequence = htons((unsigned short)i);
        icmp_hdr->checksum = 0;
        icmp_hdr->checksum = calculate_checksum((unsigned short *)icmp_hdr, sizeof(struct icmphdr));

        if (sendto(raw_sock, icmp_packet, sizeof(struct icmphdr), 0,
                   (struct sockaddr *)&target, addrlen) == -1) {
            /* Non-fatal; some systems restrict sendto on raw sockets */
            /* perror("sendto"); */
            continue;
        }

        memset(recvbuf, 0, sizeof(recvbuf));
        struct sockaddr_in reply_addr;
        socklen_t reply_len = sizeof(reply_addr);
        ssize_t recv_bytes = recvfrom(raw_sock, recvbuf, sizeof(recvbuf), 0,
                                      (struct sockaddr *)&reply_addr, &reply_len);
        if (recv_bytes <= 0) {
            /* timeout or error - skip */
            if (recv_bytes < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
                /* non-timeout error (optional debug) */
                /* perror("recvfrom"); */
            }
            continue;
        }

        /* Received some data — extract source IP from IP header portion of recvbuf */
        if ((size_t)recv_bytes < sizeof(struct iphdr)) {
            continue;
        }
        struct iphdr *recv_iph = (struct iphdr *)recvbuf;
        struct in_addr src_addr;
        src_addr.s_addr = recv_iph->saddr;

        char src_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip_str, sizeof(src_ip_str));

        /* Check uniqueness */
        int duplicate = 0;
        for (int k = 0; k < num_active; ++k) {
            if (strcmp(src_ip_str, active_hosts[k]) == 0) {
                duplicate = 1;
                break;
            }
        }

        if (!duplicate && num_active < MAX_ACTIVE_HOSTS) {
            strncpy(active_hosts[num_active], src_ip_str, INET_ADDRSTRLEN);
            active_hosts[num_active][INET_ADDRSTRLEN-1] = '\0';
            num_active++;
            printf("Active Host: %s\n", src_ip_str);

            /* Scan ports on discovered host */
            scan_ports(src_ip_str);
        }
    }

    close(raw_sock);
}

int main(void) {
    char network[32];

    printf("Enter the network to scan (e.g. 192.168.1.0 or 192.168.1): ");
    if (scanf("%31s", network) != 1) {
        fprintf(stderr, "Failed to read network base\n");
        return EXIT_FAILURE;
    }

    /* Note: program will iterate .1 .. .255 based on the given base */
    scan_network(network);
    return 0;
}
