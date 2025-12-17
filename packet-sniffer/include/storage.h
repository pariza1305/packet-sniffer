#ifndef STORAGE_H
#define STORAGE_H

#include <pcap.h>

#define MAX_PACKETS 10000

void clear_packet_storage();
void add_packet_to_storage(const struct pcap_pkthdr *header, const u_char *packet);
void inspect_session();

#endif // STORAGE_H