#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/time.h>  // For gettimeofday

#include "fill_packet.h"
#include "pcap.h"


pid_t pid;
// Store the send time globally to compare with the receive time
struct timeval send_time;
struct timeval recv_time;

// Function to capture the send timestamp
void record_send_time() {
    gettimeofday(&send_time, NULL);  // Get current time in seconds and microseconds
}

// Function to capture the receive timestamp and calculate the time difference
void record_receive_time() {
    gettimeofday(&recv_time, NULL);  // Get current time when packet is received
    // Calculate time difference in microseconds
    long seconds = recv_time.tv_sec - send_time.tv_sec;
    long microseconds = recv_time.tv_usec - send_time.tv_usec;

    if (microseconds < 0) {
        microseconds += 1000000;  // Adjust if negative
        seconds -= 1;
    }

    printf("time : %06ld ms\n", microseconds/1000);
}

int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	
	pid = getpid();
	struct sockaddr_in dst;
	//myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	// int count = DEFAULT_SEND_COUNT;
	// int timeout = DEFAULT_TIMEOUT;
	
	if (argc != 5){
		printf("usage: sudo ./ipscanner -i [Network Interface Name] -t [timeout(ms)]\n");
	}
	/*
	 * part one: parse the interface card's ip
	 */
	struct ifreq ifr;
	char *ip_str = malloc(INET_ADDRSTRLEN);;
	char *mask_str = malloc(INET_ADDRSTRLEN);;
	// Create a socket for ioctl calls
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Get IP address of the device
    strncpy(ifr.ifr_name, argv[2], IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("Unable to get IP address");
        close(sockfd);
		exit(1);
	}
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    // Save the IP address
    uint32_t saved_ip = ip_addr->sin_addr.s_addr;
    strcpy(ip_str, inet_ntoa(ip_addr->sin_addr));

    // Get subnet mask
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("Unable to get subnet mask");
        close(sockfd);
        exit(1);
    }

	
    struct sockaddr_in *mask_addr = (struct sockaddr_in *)&ifr.ifr_netmask;
	// Save the mask address
	uint32_t saved_mask = mask_addr->sin_addr.s_addr;
    strcpy(mask_str, inet_ntoa(mask_addr->sin_addr));

    printf("Device: %s\n", argv[2]);
    printf("IP Address: %s\n", ip_str);
    printf("Subnet Mask: %s\n", mask_str);

    /*
	 * create socket for sending packet
	 */
    int seq = 1; // Sequence number starts at 1
    const char *student_id = "M133040019";
    int student_id_len = strlen(student_id);

	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}

	/* 
	 * loop
	 */
	for (uint32_t addr = ntohl(saved_ip & saved_mask) + 1; addr < ntohl(saved_ip | ~saved_mask); addr++) {
        struct in_addr current_addr;
        current_addr.s_addr = htonl(addr);
		// do not send to myself
		if (saved_ip == current_addr.s_addr) {
			continue;
		}
        printf("PING %s (data size = %d, id = 0x%04x, seq = %d, timeout = %d ms)\n", 
		inet_ntoa(current_addr), student_id_len, getpid(), seq, atoi(argv[4]));

		/*
		 * my pcap init 
		 */
		my_pcap_init(ip_str, argv[2], atoi(argv[4]));
		/*
		 *   1. packet declaration
		 */
	    int packet_len = sizeof(struct ip) + sizeof(struct icmphdr) + student_id_len;
		u8 *send_buf = (u8 *)malloc(packet_len);
		myicmp *packet = (myicmp *)send_buf;

		/*
		 *   2. Destination address
		 */
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(addr);

		/*
		 *   3. Fill IP header
		 */
		fill_iphdr(&packet->ip_hdr, inet_ntoa(current_addr), ip_str, packet_len);

        /*
		 *   4. Fill ICMP header
		 */
		fill_icmphdr(&packet->icmp_hdr, seq);
        
		// Fill data with Student ID
        memcpy(packet->data, student_id, student_id_len);
		
		// re-calculate the checksum after appending data
		packet->icmp_hdr.checksum = fill_cksum(&packet->icmp_hdr, sizeof(struct icmphdr) + student_id_len);
        
		/*
	 	*   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		*   or use the standard socket like the one in the ARP homework
 	 	*   to get the "ICMP echo response" packets 
	 	*	You should reset the timer every time before you send a packet.
	 	*/
		
		// Send the packet
	    record_send_time();
        if (sendto(sockfd, send_buf, packet_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto failed");
			exit(1);
		}
		// Capture packets
		int ret = pcap_get_reply(atoi(argv[4]));
		if (ret > 0)
			record_receive_time();
		
        seq++; // Increment sequence number
		free(send_buf);
	}
	return 0;
}

