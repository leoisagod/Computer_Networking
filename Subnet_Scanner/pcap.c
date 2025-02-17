#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/ip.h>  // For IP header struct
#include <arpa/inet.h>   // For inet_ntoa()

extern pid_t pid;
extern u16 icmp_req;

//static const char* dev = "eth0";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE]="";

static pcap_t *p;
//static struct pcap_pkthdr *hdr;

void parse_and_print_src_ip(const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);  // IP header starts after Ethernet header (14 bytes)

    // Print source IP address
    printf("\tReply from : %s , ", inet_ntoa(ip_header->ip_src));  // inet_ntoa converts the in_addr to string
}
/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */

void my_pcap_init( const char* dst_ip ,const char* device, int timeout )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	
	struct bpf_program fcode;
	
	ret = pcap_lookupnet(device, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;
	net = inet_ntoa(addr);	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	
	p = pcap_open_live(device, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	int ze = 0;
    snprintf(filter_string, sizeof(filter_string), "icmp and icmp[0] = %d", ze);
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}

volatile sig_atomic_t timeout_flag = 0;  // Flag to indicate timeout occurred

// Signal handler for SIGALRM
void timeout_handler(int sig) {
    timeout_flag = 1;  // Set the flag when alarm signal is received
	pcap_breakloop(p);
}

int pcap_get_reply( int timeout_ms )
{
	const u_char *ptr;
    // Set an alarm to go off after 'timeout_sec' seconds
	int timeout_sec = timeout_ms / 1000;
	int timeout_usec = (timeout_ms - timeout_sec * 1000)*1000;
	struct itimerval timer;
    struct pcap_pkthdr header;
    // Register signal handler for SIGALRM
    signal(SIGALRM, timeout_handler);

    // Configure the timer to expire after 500ms (0.5 seconds)
    timer.it_value.tv_sec = timeout_sec;          // Seconds
    timer.it_value.tv_usec = timeout_usec;   // Microseconds (500ms)

    // Configure the timer to reset every 500ms after it expires
    timer.it_interval.tv_sec = timeout_sec;      // Seconds
    timer.it_interval.tv_usec = timeout_usec; // Microseconds (500ms)

    // Start the timer
    setitimer(ITIMER_REAL, &timer, NULL);

    // Capture the next packet
    ptr = pcap_next(p, &header);

    // Check if timeout occurred
    if (timeout_flag) {
        printf("\tDestination Ureachable\n");
        timeout_flag = 0;  // Reset the timeout flag
        return 0; // Timeout occurred
    }

    // If no timeout, process the packet
    if (ptr) {
		// IP header starts after Ethernet header
		parse_and_print_src_ip(ptr);
        return 1; // Successfully captured a packet
    } else {
        fprintf(stderr, "Error capturing packet: %s\n", pcap_geterr(p));
        return -1; // Error occurred
    }
}
