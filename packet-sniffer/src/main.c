#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "sniffer.h"
#include "storage.h"

// This is a global variable from the sniffer module
extern pcap_t *handle; 

void handle_sigint(int sig) {
    (void)sig; // Unused parameter
    printf("\n[C-Shark] Capture stopped.\n");
    if (handle) {
        pcap_breakloop(handle);
    }
}

void print_main_menu(const char *dev) {
    printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", dev);
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n");
    printf(">> ");
}

void print_filter_menu() {
    printf("\n[C-Shark] Select a filter:\n\n");
    printf("1. HTTP (port 80)\n");
    printf("2. HTTPS (port 443)\n");
    printf("3. DNS (port 53)\n");
    printf("4. ARP\n");
    printf("5. TCP\n");
    printf("6. UDP\n");
    printf(">> ");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    int i = 0;
    int choice;
    char dev_name[128] = {0};

    signal(SIGINT, handle_sigint);

    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces... Found!\n\n");

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap or libpcap is installed.\n");
        return 1;
    }

    printf("\nSelect an interface to sniff (1-%d): ", i);
    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Invalid input.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    // Clear the input buffer
    while (getchar() != '\n'); 

    if (choice < 1 || choice > i) {
        printf("Invalid selection.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    i = 0;
    for (d = alldevs; d && i < choice - 1; d = d->next, i++);
    strncpy(dev_name, d->name, sizeof(dev_name) - 1);
    pcap_freealldevs(alldevs);

    int running = 1;
    while(running) {
        print_main_menu(dev_name);
        if (scanf("%d", &choice) != 1) {
            printf("\n[C-Shark] Exiting cleanly. Goodbye!\n"); // Catches Ctrl+D
            running = 0;
            continue;
        }
         while (getchar() != '\n'); // Clear buffer

        switch(choice) {
            case 1:
                start_sniffing(dev_name, NULL);
                break;
            case 2: {
                print_filter_menu();
                int filter_choice;
                if (scanf("%d", &filter_choice) != 1) {
                    printf("\n[C-Shark] Exiting cleanly. Goodbye!\n"); // Catches Ctrl+D
                    running = 0;
                    continue;
                }
                while (getchar() != '\n'); // Clear buffer
                
                char *filter = NULL;
                switch (filter_choice) {
                    case 1: filter = "tcp port 80"; break;
                    case 2: filter = "tcp port 443"; break;
                    case 3: filter = "udp port 53"; break;
                    case 4: filter = "arp"; break;
                    case 5: filter = "tcp"; break;
                    case 6: filter = "udp"; break;
                    default: printf("Invalid filter choice.\n"); break;
                }
                if (filter) {
                    start_sniffing(dev_name, filter);
                }
                break;
            }
            case 3:
                inspect_session();
                break;
            case 4:
                running = 0;
                printf("[C-Shark] Exiting. Have a nice day!\n");
                break;
            default:
                printf("Invalid option. Please try again.\n");
                break;
        }
    }
    
    clear_packet_storage(); // Final cleanup
    return 0;
}