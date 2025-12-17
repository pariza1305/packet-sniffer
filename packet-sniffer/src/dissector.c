// code from llm 
#include "dissector.h"
#include "utils.h"
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

// Forward declarations for internal functions
static void dissect_l2(const u_char **packet, int *len, int packet_id, int verbose);
static void dissect_l3_ipv4(const u_char *packet, int len, int packet_id, int verbose);
static void dissect_l3_ipv6(const u_char *packet, int len, int packet_id, int verbose);
static void dissect_l3_arp(const u_char *packet, int len, int packet_id, int verbose);
static void dissect_l4_tcp(const u_char *packet, int len, int packet_id, int verbose, int l3_payload_len);
static void dissect_l4_udp(const u_char *packet, int len, int packet_id, int verbose, int l3_payload_len);
static void dissect_l7_payload(const u_char *packet, int len, int src_port, int dst_port, int verbose);

void dissect_packet(const struct pcap_pkthdr *header, const u_char *packet, int packet_id) {
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
           packet_id, header->ts.tv_sec, header->ts.tv_usec, header->len);

    int len = header->caplen;
    dissect_l2(&packet, &len, packet_id, 0); // 0 for non-verbose
}

void inspect_packet_details(const struct pcap_pkthdr *header, const u_char *packet, int packet_id) {
    printf("\n======================================================\n");
    printf("              IN-DEPTH PACKET ANALYSIS (#%d)\n", packet_id);
    printf("======================================================\n");
    printf("Captured Length: %d bytes | Original Length: %d bytes\n", header->caplen, header->len);
    printf("Timestamp: %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);
    
    int len = header->caplen;
    dissect_l2(&packet, &len, packet_id, 1); // 1 for verbose

    printf("\n--- Full Packet Hex Dump ---\n");
    print_hex_ascii_dump(packet - header->caplen + len, header->caplen); // Go back to start
    printf("======================================================\n");
}


// --- Layer 2: Ethernet ---
static void dissect_l2(const u_char **packet, int *len, int packet_id, int verbose) {
    if (*len < sizeof(struct ether_header)) {
        printf("L2 (Ethernet): Incomplete header\n");
        return;
    }

    struct ether_header *eth_header = (struct ether_header *)*packet;
    u_short ether_type = ntohs(eth_header->ether_type);

    if (verbose) {
        printf("\n--- Layer 2: Ethernet Header ---\n");
        printf("Destination MAC: "); print_mac_address(eth_header->ether_dhost); printf("\n");
        printf("Source MAC:      "); print_mac_address(eth_header->ether_shost); printf("\n");
        printf("EtherType:       0x%04x\n", ether_type);
    } else {
        printf("L2 (Ethernet): Dst MAC: "); print_mac_address(eth_header->ether_dhost);
        printf(" | Src MAC: "); print_mac_address(eth_header->ether_shost); printf(" |\n");
    }

    // Move packet pointer and length past the Ethernet header
    *packet += sizeof(struct ether_header);
    *len -= sizeof(struct ether_header);
    
    switch (ether_type) {
        case ETHERTYPE_IP:
            if (!verbose) printf("EtherType: IPv4 (0x%04x)\n", ether_type);
            dissect_l3_ipv4(*packet, *len, packet_id, verbose);
            break;
        case ETHERTYPE_IPV6:
             if (!verbose) printf("EtherType: IPv6 (0x%04x)\n", ether_type);
            dissect_l3_ipv6(*packet, *len, packet_id, verbose);
            break;
        case ETHERTYPE_ARP:
             if (!verbose) printf("EtherType: ARP (0x%04x)\n", ether_type);
            dissect_l3_arp(*packet, *len, packet_id, verbose);
            break;
        default:
            printf("EtherType: Unknown (0x%04x)\n", ether_type);
            break;
    }
}

// --- Layer 3: IPv4 ---
static void dissect_l3_ipv4(const u_char *packet, int len, int packet_id, int verbose) {
    if (len < sizeof(struct ip)) {
        printf("L3 (IPv4): Incomplete header\n");
        return;
    }

    const struct ip *ip_header = (const struct ip *)packet;
    int header_len = ip_header->ip_hl * 4;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    if(verbose) {
        printf("\n--- Layer 3: IPv4 Header ---\n");
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);
        printf("Protocol: %u | TTL: %u | Total Length: %u | Header Length: %d bytes\n", 
               ip_header->ip_p, ip_header->ip_ttl, ntohs(ip_header->ip_len), header_len);
        printf("ID: 0x%04x | Checksum: 0x%04x\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_sum));
    } else {
        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%u) | TTL: %u\n",
               src_ip, dst_ip, 
               (ip_header->ip_p == IPPROTO_TCP) ? "TCP" : (ip_header->ip_p == IPPROTO_UDP) ? "UDP" : "Other", 
               ip_header->ip_p, ip_header->ip_ttl);
        printf("ID: 0x%04x | Total Length: %u | Header Length: %d bytes\n",
               ntohs(ip_header->ip_id), ntohs(ip_header->ip_len), header_len);
    }
    
    packet += header_len;
    len -= header_len;
    
    int l3_payload_len = ntohs(ip_header->ip_len) - header_len;

    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            dissect_l4_tcp(packet, len, packet_id, verbose, l3_payload_len);
            break;
        case IPPROTO_UDP:
            dissect_l4_udp(packet, len, packet_id, verbose, l3_payload_len);
            break;
        default:
            printf("L4: Other (Protocol: %d)\n", ip_header->ip_p);
            break;
    }
}

// --- Layer 3: IPv6 ---
static void dissect_l3_ipv6(const u_char *packet, int len, int packet_id, int verbose) {
     if (len < sizeof(struct ip6_hdr)) {
        printf("L3 (IPv6): Incomplete header\n");
        return;
    }

    const struct ip6_hdr *ip6_header = (const struct ip6_hdr *)packet;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    
    uint32_t flow_info = ntohl(ip6_header->ip6_flow);
    uint8_t traffic_class = (flow_info >> 20) & 0xFF;
    uint32_t flow_label = flow_info & 0xFFFFF;

    if (verbose) {
        printf("\n--- Layer 3: IPv6 Header ---\n");
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);
        printf("Next Header: %u | Hop Limit: %u | Payload Length: %u\n",
               ip6_header->ip6_nxt, ip6_header->ip6_hlim, ntohs(ip6_header->ip6_plen));
        printf("Traffic Class: %u | Flow Label: 0x%05x\n", traffic_class, flow_label);
    } else {
        printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip, dst_ip);
        printf("Next Header: %s (%u) | Hop Limit: %u | Traffic Class: %u | Flow Label: 0x%05x | Payload Length: %u\n",
            (ip6_header->ip6_nxt == IPPROTO_TCP) ? "TCP" : (ip6_header->ip6_nxt == IPPROTO_UDP) ? "UDP" : "Other",
            ip6_header->ip6_nxt, ip6_header->ip6_hlim, traffic_class, flow_label, ntohs(ip6_header->ip6_plen));
    }
    
    packet += sizeof(struct ip6_hdr);
    len -= sizeof(struct ip6_hdr);

    int l3_payload_len = ntohs(ip6_header->ip6_plen);

    switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            dissect_l4_tcp(packet, len, packet_id, verbose, l3_payload_len);
            break;
        case IPPROTO_UDP:
            dissect_l4_udp(packet, len, packet_id, verbose, l3_payload_len);
            break;
        default:
            printf("L4: Other (Next Header: %d)\n", ip6_header->ip6_nxt);
            break;
    }
}

// --- Layer 3: ARP ---
static void dissect_l3_arp(const u_char *packet, int len, int packet_id, int verbose) {
    if (len < sizeof(struct arphdr)) {
        printf("L3 (ARP): Incomplete header\n");
        return;
    }

    const struct arphdr *arp_header = (const struct arphdr *)packet;
    const u_char *arp_payload = packet + sizeof(struct arphdr);

    char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
    // ARP payload structure: sender MAC, sender IP, target MAC, target IP
    inet_ntop(AF_INET, arp_payload + arp_header->ar_hln, sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_payload + arp_header->ar_hln * 2 + arp_header->ar_pln, target_ip, INET_ADDRSTRLEN);

    if (verbose) {
         printf("\n--- Layer 3: ARP Header ---\n");
         printf("Operation: %s (%d)\n", (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply", ntohs(arp_header->ar_op));
         printf("Hardware Type: %u | Protocol Type: 0x%04x\n", ntohs(arp_header->ar_hrd), ntohs(arp_header->ar_pro));
         printf("HW Len: %u | Proto Len: %u\n", arp_header->ar_hln, arp_header->ar_pln);
         printf("Sender MAC: "); print_mac_address(arp_payload); printf(" | Sender IP: %s\n", sender_ip);
         printf("Target MAC: "); print_mac_address(arp_payload + arp_header->ar_hln + arp_header->ar_pln); printf(" | Target IP: %s\n", target_ip);
    } else {
        printf("L3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
               (ntohs(arp_header->ar_op) == ARPOP_REQUEST) ? "Request" : "Reply",
               ntohs(arp_header->ar_op), sender_ip, target_ip);
        printf("Sender MAC: "); print_mac_address(arp_payload);
        printf(" | Target MAC: "); print_mac_address(arp_payload + arp_header->ar_hln + arp_header->ar_pln); printf("\n");
        printf("HW Type: %u | Proto Type: 0x%04x | HW Len: %u | Proto Len: %u\n",
               ntohs(arp_header->ar_hrd), ntohs(arp_header->ar_pro), arp_header->ar_hln, arp_header->ar_pln);
    }
}

// --- Layer 4: TCP ---
static void dissect_l4_tcp(const u_char *packet, int len, int packet_id, int verbose, int l3_payload_len) {
     if (len < sizeof(struct tcphdr)) {
        printf("L4 (TCP): Incomplete header\n");
        return;
    }
    
    const struct tcphdr *tcp_header = (const struct tcphdr *)packet;
    int header_len = tcp_header->th_off * 4;
    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);

    if (verbose) {
        printf("\n--- Layer 4: TCP Header ---\n");
        printf("Source Port: %d (%s)\n", src_port, port_to_service(src_port));
        printf("Destination Port: %d (%s)\n", dst_port, port_to_service(dst_port));
        printf("Sequence Number: %u\n", ntohl(tcp_header->th_seq));
        printf("Ack Number: %u\n", ntohl(tcp_header->th_ack));
        printf("Flags: %s (0x%02x)\n", get_tcp_flag_string(tcp_header->th_flags), tcp_header->th_flags);
        printf("Window Size: %u | Checksum: 0x%04x | Header Length: %d bytes\n", 
            ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum), header_len);
    } else {
        printf("L4 (TCP): Src Port: %d (%s) | Dst Port: %d (%s) | Seq: %u | Ack: %u | Flags: %s\n",
               src_port, port_to_service(src_port),
               dst_port, port_to_service(dst_port),
               ntohl(tcp_header->th_seq), ntohl(tcp_header->th_ack),
               get_tcp_flag_string(tcp_header->th_flags));
        printf("Window: %u | Checksum: 0x%04x | Header Length: %d bytes\n",
               ntohs(tcp_header->th_win), ntohs(tcp_header->th_sum), header_len);
    }
    
    packet += header_len;
    len -= header_len;
    int payload_len = l3_payload_len - header_len;

    if (payload_len > 0) {
        dissect_l7_payload(packet, payload_len, src_port, dst_port, verbose);
    }
}

// --- Layer 4: UDP ---
static void dissect_l4_udp(const u_char *packet, int len, int packet_id, int verbose, int l3_payload_len) {
    if (len < sizeof(struct udphdr)) {
        printf("L4 (UDP): Incomplete header\n");
        return;
    }

    const struct udphdr *udp_header = (const struct udphdr *)packet;
    int src_port = ntohs(udp_header->uh_sport);
    int dst_port = ntohs(udp_header->uh_dport);
    int udp_len = ntohs(udp_header->uh_ulen);

    if (verbose) {
        printf("\n--- Layer 4: UDP Header ---\n");
        printf("Source Port: %d (%s)\n", src_port, port_to_service(src_port));
        printf("Destination Port: %d (%s)\n", dst_port, port_to_service(dst_port));
        printf("Length: %u | Checksum: 0x%04x\n", udp_len, ntohs(udp_header->uh_sum));
    } else {
        printf("L4 (UDP): Src Port: %d (%s) | Dst Port: %d (%s) | Length: %u | Checksum: 0x%04x\n",
               src_port, port_to_service(src_port),
               dst_port, port_to_service(dst_port),
               udp_len, ntohs(udp_header->uh_sum));
    }
    
    packet += sizeof(struct udphdr);
    len -= sizeof(struct udphdr);
    int payload_len = udp_len - sizeof(struct udphdr);

    if (payload_len > 0) {
        dissect_l7_payload(packet, payload_len, src_port, dst_port, verbose);
    }
}

// --- Layer 7: Payload ---
static void dissect_l7_payload(const u_char *packet, int len, int src_port, int dst_port, int verbose) {
    const char *protocol = "Unknown";
    if ((src_port == 80 || dst_port == 80)) protocol = "HTTP";
    else if ((src_port == 443 || dst_port == 443)) protocol = "HTTPS/TLS";
    else if ((src_port == 53 || dst_port == 53)) protocol = "DNS";

    if (verbose) {
        printf("\n--- Layer 7: Payload Data ---\n");
        printf("Identified Protocol: %s | Payload Length: %d bytes\n", protocol, len);
    } else {
         printf("L7 (Payload): Identified as %s on port %d - %d bytes\n", 
               protocol, (dst_port == 80 || dst_port == 443 || dst_port == 53) ? dst_port : src_port, len);
    }
    
    printf("Data (first 64 bytes):\n");
    print_hex_ascii_dump(packet, (len > 64) ? 64 : len);
}