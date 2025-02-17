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
#include "utils.h"

int main(int argc, char *argv[]) {
    /*
     *  parse input and create socket
     */
    if (argc != 3) {
        fprintf(stderr, "Usage: sudo %s <hops> <destination IP>\n", argv[0]);
        exit(1);
    }
    int hops = atoi(argv[1]);
    char *dest_ip = argv[2];

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        if (errno == 1)
			printf("ERROR: You must be root to use this tool!\n");
		else
			perror("open recv socket error");
		exit(1);
        return -1;
    }

    /*
     *  set destination address
     */
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    if (inet_pton(AF_INET, dest_ip, &addr.sin_addr) <= 0) {
        perror("Invalid IP address");
        return -1;
    }

    /*
     *  main ERS loop
     */
    for (int ttl = 1; ttl <= hops; ttl++) {
        send_probe(sockfd, &addr, ttl);
        printf("Hop: %d,  ", ttl);
        int response=receive_response(sockfd, &addr); 
        if (response == 0 && ttl == hops) {
            printf("Reached %d-hop router to %s\n", ttl, dest_ip);
            break;
        }
        else if (response == 1){
            printf("Reached Destination %s with %d-hop\n", dest_ip, ttl);
            break;
        }
        else if (response == -1){
            printf("timeout error: cannot reach the next hop before 5 seconds\n");
            break;
        }
        sleep(1);  // Wait between probes
    }

    close(sockfd);
    return 0;
}
