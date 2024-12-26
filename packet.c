#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define FLTRSZ 120
#define MAXHOSTSZ 256
#define ADDR_STRSZ 16

extern char *inet_ntoa();

int main(int argc, char **argv) {
    pcap_t *p;               /* packet capture descriptor */
    pcap_dumper_t *pd;       /* pointer to the dump file */
    char *ifname = NULL;     /* interface name (such as "en0") */
    char errbuf[PCAP_ERRBUF_SIZE];  /* buffer to hold error text */
    char lhost[MAXHOSTSZ];   /* local host name */
    char fltstr[FLTRSZ];     /* bpf filter string */
    char prestr[80];         /* prefix string for errors from pcap_perror */
    struct bpf_program prog; /* compiled bpf filter program */
    int optimize = 1;        /* passed to pcap_compile to do optimization */
    int snaplen = 80;        /* amount of data per packet */
    int promisc = 0;         /* do not change mode; if in promiscuous mode, stay in it, otherwise, do not */
    int to_ms = 1000;        /* timeout, in milliseconds */
    int count = 20;          /* number of packets to capture */
    u_int32_t net = 0;       /* network IP address */
    u_int32_t mask = 0;      /* network address mask */
    char netstr[INET_ADDRSTRLEN];   /* dotted decimal form of address */
    char maskstr[INET_ADDRSTRLEN];  /* dotted decimal form of net mask */

    /*
     * Find a network device on the system using pcap_findalldevs().
     */
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(1);
    }

    if (alldevs == NULL) {
        fprintf(stderr, "No devices found.\n");
        exit(2);
    }

    ifname = alldevs->name;  // Use the first available device
    printf("Using device: %s\n", ifname);

    /*
     * Open the network device for packet capture.
     */
    if (!(p = pcap_open_live(ifname, snaplen, promisc, to_ms, errbuf))) {
        fprintf(stderr, "Error opening interface %s: %s\n", ifname, errbuf);
        exit(3);
    }

    /*
     * Look up the network address and subnet mask for the network device.
     */
    if (pcap_lookupnet(ifname, &net, &mask, errbuf) < 0) {
        fprintf(stderr, "Error looking up network: %s\n", errbuf);
        exit(4);
    }

    /*
     * Get the hostname of the local system.
     */
    if (gethostname(lhost, sizeof(lhost)) < 0) {
        fprintf(stderr, "Error getting hostname.\n");
        exit(5);
    }

    /*
     * Get the dotted decimal representation of the network address and netmask.
     */
    inet_ntop(AF_INET, (char*) &net, netstr, sizeof netstr);
    inet_ntop(AF_INET, (char*) &mask, maskstr, sizeof maskstr);

    /*
     * Create a filter to capture incoming packets on port 23 (Telnet).
     */
    sprintf(fltstr, "ip");

    /*
     * Compile the filter.
     */
    if (pcap_compile(p, &prog, fltstr, optimize, mask) < 0) {
        fprintf(stderr, "Error compiling bpf filter on %s: %s\n", ifname, pcap_geterr(p));
        exit(6);
    }

    /*
     * Load the compiled filter program into the packet capture device.
     */
    if (pcap_setfilter(p, &prog) < 0) {
        sprintf(prestr, "Error installing bpf filter on interface %s", ifname);
        pcap_perror(p, prestr);
        exit(7);
    }

    /*
     * Open the dump device to save packets to a file.
     */
    if ((pd = pcap_dump_open(p, "capture.pcap")) == NULL) {
        fprintf(stderr, "Error opening dump file capture.pcap: %s\n", pcap_geterr(p));
        exit(8);
    }

    /*
     * Capture packets and save them to the file.
     */
    if (pcap_loop(p, count, &pcap_dump, (char *)pd) < 0) {
        sprintf(prestr, "Error reading packets from interface %s", ifname);
        pcap_perror(p, prestr);
        exit(9);
    }

    /*
     * Close the packet capture device and the dump file.
     */
    pcap_close(p);
    pcap_dump_close(pd);

    printf("Packet capture saved to capture.pcap\n");

    /* Free the device list */
    pcap_freealldevs(alldevs);

    return 0;
}

