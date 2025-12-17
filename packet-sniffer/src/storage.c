#include "storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "dissector.h"
#include "utils.h"
// code from llm 
// Define a structure to hold a captured packet
typedef struct {
    struct pcap_pkthdr header;
    u_char *packet_data;
} captured_packet;

static captured_packet packet_storage[MAX_PACKETS];
static int session_packet_count = 0;
static int has_session_run = 0;

void clear_packet_storage() {
    for (int i = 0; i < session_packet_count; i++) {
        free(packet_storage[i].packet_data);
        packet_storage[i].packet_data = NULL;
    }
    session_packet_count = 0;
}

void add_packet_to_storage(const struct pcap_pkthdr *header, const u_char *packet) {
    if (session_packet_count >= MAX_PACKETS) {
        return; // Storage is full
    }

    // Allocate new memory and copy the packet data
    u_char *packet_copy = malloc(header->caplen);
    if (!packet_copy) {
        perror("Failed to allocate memory for packet copy");
        return;
    }
    memcpy(packet_copy, packet, header->caplen);

    packet_storage[session_packet_count].header = *header;
    packet_storage[session_packet_count].packet_data = packet_copy;
    session_packet_count++;
    has_session_run = 1;
}

void inspect_session() {
    if (!has_session_run) {
        printf("\n[C-Shark] No session has been run yet. Start sniffing first.\n");
        return;
    }
    if (session_packet_count == 0) {
        printf("\n[C-Shark] The last session captured 0 packets.\n");
        return;
    }

    printf("\n--- Last Session Summary (%d packets) ---\n", session_packet_count);
     for (int i = 0; i < session_packet_count; i++) {
        const struct ip *ip_header = (const struct ip *)(packet_storage[i].packet_data + 14); // Assuming Ethernet
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        printf("ID: %-5d | Time: %ld.%06ld | Len: %-5d | %s -> %s\n",
               i + 1,
               packet_storage[i].header.ts.tv_sec,
               packet_storage[i].header.ts.tv_usec,
               packet_storage[i].header.len,
               src_ip,
               dst_ip);
    }
    printf("----------------------------------------\n");

    int packet_id = 0;
    printf("Enter Packet ID to inspect (1-%d): ", session_packet_count);
    if(scanf("%d", &packet_id) != 1) {
        printf("\n[C-Shark] Invalid input. Returning to menu.\n");
        while(getchar()!='\n'); // Clear buffer
        return;
    }
    while(getchar()!='\n'); // Clear buffer

    if (packet_id < 1 || packet_id > session_packet_count) {
        printf("[C-Shark] Invalid Packet ID.\n");
        return;
    }

    const captured_packet *pkt = &packet_storage[packet_id - 1];
    inspect_packet_details(&pkt->header, pkt->packet_data, packet_id);
}