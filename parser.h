#ifndef __PARSER_H_
#define __PARSER_H_

#include <stdint.h>
#include <pcap.h>

uint16_t anonimize(uint16_t datalink, const struct pcap_pkthdr* hdr, const unsigned char* pkt);

#endif
