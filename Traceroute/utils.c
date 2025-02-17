#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

/*
 *  Function to calculate checksum for ICMP packet
 *  input:
 *      b: input packet
 *      len: packet size
 *  return: checksum
 */ 
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;  // binary string
    unsigned int sum = 0;
    // add to sum
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1) // if odd byte, add this remainder
        sum += *(unsigned char*)buf;
    // any carry from the high 16 bits is folded back into the lower 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}
/*
 *  Function to send ICMP echo requests with specified TTL
 *  input:
 *      sockfd: socket file descriptor
 *      addr: destination address
 *      ttl: ttl to set, as well as the current hop index
 */ 
void send_probe(int sockfd, struct sockaddr_in *addr, int ttl) {
    char packet[PACKET_SIZE];
    struct icmp *icmp_hdr = (struct icmp*) packet;

    memset(packet, 0, PACKET_SIZE);

    icmp_hdr->icmp_type = ICMP_ECHO; // ICMP ECHO
    icmp_hdr->icmp_code = 0;  // code 0: ECHO_REQUEST
    icmp_hdr->icmp_id = getpid();  // set process ID
    icmp_hdr->icmp_seq = ttl;  // sequence number = ttl sequence
    icmp_hdr->icmp_cksum = checksum(packet, PACKET_SIZE);

    // Set the socket option to specify the TTL (hop count)
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) != 0) {
        perror("Failed to set TTL");
        exit(1);
    }

    // Send the packet
    if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr*) addr, sizeof(*addr)) <= 0) {
        perror("Send failed");
        return;
    }
}

/*
 *  Function to receive IGMP reponse
 *  input:
 *      sockfd: socket file descriptor
 *      addr: destination address
 *  return: integer that indicates response type
 *      0: time exceed response; router ip for the hop found
 *      1: echo reply response; target ip found
 *     -1: socket timeout; terminates the program
 */ 
int receive_response(int sockfd, struct sockaddr_in *addr) {
    char buf[PACKET_SIZE];
    struct sockaddr_in response_addr;
    socklen_t addr_len = sizeof(response_addr);

    // Set a 5-second timeout for receiving packet
    struct timeval timeout;
    timeout.tv_sec = 5;   // Set timeout seconds
    timeout.tv_usec = 0;  // Set timeout microseconds
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));  // SO_RCVTIMEO = receive timeout option


    // Receive response with timeout
    if (recvfrom(sockfd, buf, PACKET_SIZE, 0, (struct sockaddr*)&response_addr, &addr_len) > 0) {
        struct ip *ip_hdr = (struct ip*) buf;
        struct icmp *icmp_hdr = (struct icmp*)(buf + (ip_hdr->ip_hl << 2));
        
        // Check if the response is a time exceeded message
        if (icmp_hdr->icmp_type == ICMP_TIME_EXCEEDED) {
            printf("IP: %s\n", inet_ntoa(response_addr.sin_addr));
            return 0;
        }
        // Check if the response is a echo reply message
        else if (icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
            printf("Destination IP: %s\n", inet_ntoa(response_addr.sin_addr));
            return 1;
        }
    }
    // time out, recvfrom returns -1
    else
        return -1;
    return -1;
}