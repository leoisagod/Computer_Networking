#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.
/*****************************************************************************/
/* Function: print usage                                                     */
/*****************************************************************************/
void print_usage(){
	printf("Format :\n1) ./arp -l -a\n2) ./arp -l <filter_ip_address>\n3) ./arp -q <query_ip_address>\n4) ./arp <fake_mac_address> <target_ip_address>\n");

}
void handler(int sig){
	printf("\nSIGINT handled\n");
}
void parse_arp(struct arp_packet *packet){
	// Check if packet is ARP
     if (ntohs(packet->eth_hdr.ether_type) == ETHERTYPE_ARP) {
        // Extract and print IP addresses
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
	    // spa: sender protocol address
        inet_ntop(AF_INET, packet->arp.arp_spa, sender_ip, sizeof(sender_ip));
        // tpa: target protocol address
        inet_ntop(AF_INET, packet->arp.arp_tpa, target_ip, sizeof(target_ip));

        char mac[INET_ADDRSTRLEN];
        strcpy(mac, ether_ntoa((struct ether_addr *)&(packet->arp.arp_sha)));
        if (ntohs(packet->arp.ea_hdr.ar_op) == ARPOP_REQUEST) {
            printf("Get ARP packet - Who has %s ? Tell %s\n", target_ip, sender_ip);
        }
        else if (ntohs(packet->arp.ea_hdr.ar_op) == ARPOP_REPLY) {
            printf("Get ARP reply - %s is at %s \n", sender_ip, mac);
        }
    }
}

void parse_arp_ip(struct arp_packet *packet, char *address){
	// Check if packet is ARP
     if (ntohs(packet->eth_hdr.ether_type) == ETHERTYPE_ARP) {
        // Extract and print IP addresses
        char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
	    // spa: sender protocol address
        inet_ntop(AF_INET, packet->arp.arp_spa, sender_ip, sizeof(sender_ip));
        // tpa: target protocol address
        inet_ntop(AF_INET, packet->arp.arp_tpa, target_ip, sizeof(target_ip));
		
        if ((ntohs(packet->arp.ea_hdr.ar_op) == ARPOP_REQUEST) && (strcmp(target_ip, address) == 0)) {
            printf("Get ARP packet - Who has %s ? Tell %s\n", target_ip, sender_ip);
        }
    }
}

void set_hard_type(struct ether_arp *packet, unsigned short int type){
    packet->ea_hdr.ar_hrd = htons(type);
}
void set_prot_type(struct ether_arp *packet, unsigned short int type){
    packet->ea_hdr.ar_pro = htons(type);
}
void set_hard_size(struct ether_arp *packet, unsigned char size){
    packet->ea_hdr.ar_hln = size; 
}
void set_prot_size(struct ether_arp *packet, unsigned char size){
    packet->ea_hdr.ar_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code){
    packet->ea_hdr.ar_op = htons(code);
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address){
    memcpy(packet->arp_sha, address, 6);
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address){
    inet_pton(AF_INET, address, packet->arp_spa);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address){
    memcpy(packet->arp_tha, address, 6);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address){
    inet_pton(AF_INET, address, packet->arp_tpa);
}

char* get_target_protocol_addr(struct ether_arp *packet){
	char* addr = malloc(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(packet->arp_tpa), addr, INET_ADDRSTRLEN);
	return addr;
}
char* get_sender_protocol_addr(struct ether_arp *packet){
	char* addr = malloc(INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(packet->arp_spa), addr, INET_ADDRSTRLEN);
	return addr;
}
char* get_sender_hardware_addr(struct ether_arp *packet){
    char* addr = malloc(INET_ADDRSTRLEN);
    strcpy(addr, ether_ntoa((struct ether_addr *)&(packet->arp_sha)));
	return addr;
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	char* addr = malloc(INET_ADDRSTRLEN);
    strcpy(addr, ether_ntoa((struct ether_addr *)&(packet->arp_tha)));
	return addr;
}
