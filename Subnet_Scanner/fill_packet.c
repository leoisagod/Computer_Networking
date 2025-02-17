#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip, const char* src_ip, int packet_size)
{
    // Fill IP header
    ip_hdr->ip_v = 4;                             // IPv4
    ip_hdr->ip_hl = 5;                             // Header length (5 * 4 = 20 bytes)
    ip_hdr->ip_tos = 0;                             // Type of service
    ip_hdr->ip_len = htons(packet_size);         // Total length
    ip_hdr->ip_id = htons(0);                       // Identification
    ip_hdr->ip_off = htons(0x4000);             // Flags (Don't Fragment)
    ip_hdr->ip_ttl = 1;                             // Time-to-Live
    ip_hdr->ip_p = IPPROTO_ICMP;             // Protocol (ICMP)
    ip_hdr->ip_src.s_addr = inet_addr(src_ip);  // Source IP
    ip_hdr->ip_dst.s_addr  = inet_addr(dst_ip);           // Destination IP
    ip_hdr->ip_sum = 0; // OS calculates checksum
}

void
fill_icmphdr (struct icmphdr *icmp_hdr, int sequence)
{
	// Fill ICMP header
    icmp_hdr->type = ICMP_ECHO;                  // Echo request
    icmp_hdr->code = 0;                          // No special code
    icmp_hdr->un.echo.id = htons(getpid());      // Process ID
    icmp_hdr->un.echo.sequence = htons(sequence); // Sequence number
    icmp_hdr->checksum = 0;

}

u16
fill_cksum(void *packet, int length)
{
    //    printf("len:%d \n", length);
    // Cast the packet to unsigned short *
    unsigned short *data = (unsigned short *)packet;
    unsigned long sum = 0;
    // Sum up 16-bit chunks
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    // Handle remaining byte, if any
    if (length == 1) {
        sum += *(unsigned char *)data;
    }

    // Add overflow bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum; // Return one's complement of sum
}