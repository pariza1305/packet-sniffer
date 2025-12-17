#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <pcap.h>

void dissect_packet(const struct pcap_pkthdr *header, const u_char *packet, int packet_id);
void inspect_packet_details(const struct pcap_pkthdr *header, const u_char *packet, int packet_id);

#endif // DISSECTOR_H