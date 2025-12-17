#include <pcap.h>
#include <stdio.h>
#include "dissector.h"
#include "storage.h"

pcap_t *handle;
static int packet_count = 0;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Unused parameter
    packet_count++;
    
    // For Phase 1, uncomment this block and comment out the dissect_packet call
    /*
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n", 
           packet_count, header->ts.tv_sec, header->ts.tv_usec, header->len);
    printf("Raw Data (first 16 bytes): ");
    for (int i = 0; i < 16 && i < header->caplen; ++i) {
        printf("%02X ", packet[i]);
    }
    printf("\n-----------------------------------------\n");
    */

    add_packet_to_storage(header, packet);
    dissect_packet(header, packet, packet_count);
}


void start_sniffing(const char *dev, const char *filter_exp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Clear previous session and reset counter
    clear_packet_storage();
    packet_count = 0;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("\n[C-Shark] Starting capture on %s... Press Ctrl+C to stop.\n", dev);
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }

    if (filter_exp != NULL) {
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        printf("[C-Shark] Filter applied: \"%s\"\n", filter_exp);
        pcap_freecode(&fp);
    }
    
    // -1 means loop forever until pcap_breakloop is called
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    handle = NULL;
}