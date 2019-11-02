#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>

void packetHandler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );

int main( int argc, char *argv[] )
{
    char *dev;
    char error[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp and dst port 80";
    bpf_u_int32 ip; 
    pcap_if_t *interfaces, *temp;
    pcap_t *handle;
    struct in_addr address;
    struct pcap_pkthdr header;
    struct bpf_program fp;
    const u_char *packet;

    if(pcap_findalldevs( &interfaces, error ) == -1)
    {
    	printf("\n");
    	printf(error);
    	return -1;
    }

    printf("Interfaces:\n");
    for( temp=interfaces; temp; temp=temp->next )
    {
        printf("%s\n", temp->name);
    }
    printf("Choose interface: ");
    scanf("%[^\n]%*c", dev); 

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error);
    if (handle == NULL) 
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, error);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, ip) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, 0, packetHandler, NULL);
    pcap_close(handle);

    printf("\n");
    return 0;


}

void packetHandler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet )
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);

    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);

    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);
    
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    
    return;
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}