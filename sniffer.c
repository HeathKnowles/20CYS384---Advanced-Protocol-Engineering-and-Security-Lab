#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    int i = 0;
    static int count = 0;
    printf("Packet Count: %d\n", ++count);
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");
    for(i=0;i<pkthdr->len;i++) {
      if(isprint(packet[i]))
          printf("%c ",packet[i]);
      else
          printf(" . ",packet[i]);
      if((i%16 == 0 && i!=0) || i == pkthdr->len-1)
          printf("\n");
    }
}

int main(int argc,char **argv) 
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* descr; 
    const u_char *packet; 
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */
 
    if(argc != 2){
        fprintf(stdout, "Usage: %s \"expression\"\n"
            ,argv[0]);
        return 0;
    } 
 
    /* Now get a device */
    dev = pcap_lookupdev(errbuf); 
     
    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    } 
        /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf); 
 
    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); 
    if(descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    } 
 
    /* Now we'll compile the filter expression*/
    if(pcap_compile(descr, &fp, argv[1], 0, netp) == -1) {
        fprintf(stderr, "Error calling pcap_compile\n");
        exit(1);
    } 
 
    /* set the filter */
    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "Error setting filter\n");
        exit(1);
    } 
 
    /* loop for callback function */
    pcap_loop(descr, -1, my_callback, NULL); 
    return 0; 
}
