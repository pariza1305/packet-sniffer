#ifndef UTILS_H
#define UTILS_H

#include <pcap.h>

void print_hex_ascii_dump(const u_char *payload, int len);
void print_mac_address(const u_char *addr);
const char* get_tcp_flag_string(u_int8_t flags);
const char* port_to_service(int port);

#endif // UTILS_H