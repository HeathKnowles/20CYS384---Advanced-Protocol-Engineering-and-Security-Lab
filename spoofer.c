#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <pcap.h>

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

void capture_packets(const char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (dumper == NULL) {
        fprintf(stderr, "Could not open pcap file: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    printf("Capturing packets... Press Ctrl+C to stop.\n");
    pcap_loop(handle, 0, pcap_dump, (unsigned char *)dumper);

    pcap_dump_close(dumper);
    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <source_ip> <dest_ip> <num_packets> <pcap_filename>\n", argv[0]);
        return -1;
    }

    const char *source_ip = argv[1];
    const char *dest_ip = argv[2];
    int num_packets = atoi(argv[3]);
    const char *pcap_filename = argv[4];

    if (num_packets <= 0) {
        fprintf(stderr, "Number of packets must be greater than 0.\n");
        return -1;
    }

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
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_header->id = htons(54321);  // Identification
    ip_header->frag_off = 0;       // Fragment offset
    ip_header->ttl = 64;           // Time-to-live
    ip_header->protocol = IPPROTO_ICMP;  // Protocol
    ip_header->saddr = inet_addr(source_ip);  // Source IP
    ip_header->daddr = inet_addr(dest_ip);    // Destination IP

    icmp_header->type = ICMP_ECHO;  // ICMP Echo Request
    icmp_header->code = 0;         // Code
    icmp_header->un.echo.id = htons(1);

    if (fork() == 0) {
        capture_packets(pcap_filename);
        exit(0);
    }

    for (int i = 0; i < num_packets; i++) {
        icmp_header->un.echo.sequence = htons(i + 1);
        icmp_header->checksum = 0;
        icmp_header->checksum = checksum((unsigned short *)icmp_header, sizeof(struct icmphdr));

        ip_header->check = 0;
        ip_header->check = checksum((unsigned short *)ip_header, sizeof(struct iphdr));

        struct sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_addr.s_addr = inet_addr(dest_ip);

        if (sendto(sock, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("Packet send failed");
        } else {
            printf("Packet %d sent from %s to %s\n", i + 1, source_ip, dest_ip);
        }

        usleep(100000);  // Wait 100ms between packets
    }

    close(sock);
    printf("All packets sent. Capture saved to %s.\n", pcap_filename);

    return 0;
}

