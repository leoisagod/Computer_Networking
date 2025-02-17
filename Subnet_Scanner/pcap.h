#ifndef __PCAP__H_
#define __PCAP__H_

#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "fill_packet.h"

#define FILTER_STRING_SIZE 128

void my_pcap_init( const char* dst_ip ,const char* device, int timeout );

int pcap_get_reply( int timeout_ms );

#endif
