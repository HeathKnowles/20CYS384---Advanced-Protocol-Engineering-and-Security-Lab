#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <source_ip> <dest_ip>\n", argv[0]);
        return -1;
    }

    const char *source_ip = argv[1];
    const char *dest_ip = argv[2];

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Failed to set IP_HDRINCL");
        return -1;
    }

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip_header = (struct iphdr *)packet;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct iphdr));

    ip_header->version = 4;
    ip_header->ihl = 5;  // Header length
    ip_header->tos = 0;  // Type of service
    ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip_header->id = htons(54321);  // Identification
    ip_header->frag_off = 0;       // Fragment offset
    ip_header->ttl = 64;           // Time-to-live
    ip_header->protocol = IPPROTO_ICMP;  // Protocol
    ip_header->check = 0;                // Checksum (calculated later)
    ip_header->saddr = inet_addr(source_ip);  // Source IP
    ip_header->daddr = inet_addr(dest_ip);    // Destination IP

    ip_header->check = checksum((unsigned short *)packet, ip_header->tot_len);

    icmp_header->type = ICMP_ECHO;  // ICMP Echo Request
    icmp_header->code = 0;         // Code
    icmp_header->checksum = 0;     // Checksum (calculated later)
    icmp_header->un.echo.id = htons(1);
    icmp_header->un.echo.sequence = htons(1);

    icmp_header->checksum = checksum((unsigned short *)icmp_header, sizeof(struct icmphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip);

    if (sendto(sock, packet, ip_header->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("Packet send failed");
    } else {
        printf("Packet sent from %s to %s\n", source_ip, dest_ip);
    }

    close(sock);
    return 0;
}

