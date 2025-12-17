#ifndef SNIFFER_H
#define SNIFFER_H

void find_and_select_device();
void start_sniffing(const char *dev, const char *filter_exp);

#endif // SNIFFER_H