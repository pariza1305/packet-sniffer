#include "utils.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <netinet/tcp.h>

void print_hex_ascii_dump(const u_char *payload, int len) {
    int i;
    const u_char *ch;

    if (len <= 0) {
        printf("    (No payload data)\n");
        return;
    }
    
    for (i = 0; i < len; i++) {
        // Print hex
        if (i % 16 == 0) {
             printf("   ");
        }
        printf("%02X ", payload[i]);
        
        // Print ASCII at end of line
        if (i % 16 == 15 || i == len - 1) {
            // Fill remaining space if not a full 16-byte line
            for (int j = 0; j < 15 - (i % 16); j++) {
                printf("   ");
            }
            
            ch = payload + (i - i % 16);
            printf("  ");
            for (int j = 0; j <= i % 16; j++) {
                if (isprint(ch[j])) {
                    printf("%c", ch[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}

void print_mac_address(const u_char *addr) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}
// code from llm starts
const char* port_to_service(int port) {
    switch (port) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 53: return "DNS";
        case 20: return "FTP-data";
        case 21: return "FTP";
        case 22: return "SSH";
        case 25: return "SMTP";
        default: return "Other";
    }
}
// code from llm ends

const char* get_tcp_flag_string(u_int8_t flags) {
    static char flag_str[50];
    strcpy(flag_str, "[");
    if (flags & TH_SYN) strcat(flag_str, "SYN,");
    if (flags & TH_ACK) strcat(flag_str, "ACK,");
    if (flags & TH_FIN) strcat(flag_str, "FIN,");
    if (flags & TH_RST) strcat(flag_str, "RST,");
    if (flags & TH_PUSH) strcat(flag_str, "PSH,");
    if (flags & TH_URG) strcat(flag_str, "URG,");
    
    size_t len = strlen(flag_str);
    if (len > 1) {
        flag_str[len - 1] = ']'; // Replace last comma
    } else {
        strcat(flag_str, "]"); // No flags
    }
    return flag_str;
}