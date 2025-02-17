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

#define PACKET_SIZE 64
#define TIMEOUT 1
// Function to calculate checksum for ICMP packet
unsigned short checksum(void *b, int len);
void send_probe(int sockfd, struct sockaddr_in *addr, int ttl);
int receive_response(int sockfd, struct sockaddr_in *addr);