#include "parser.h"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "crypto.h"

/**
 * Parse headers to get payload size
 */
static inline uint16_t parse_tcp(const unsigned char* pkt, uint16_t len)
{
	struct tcphdr *tcph;
	uint16_t hdr_len;

	if (len < sizeof(struct tcphdr))
		return 0;

	tcph = (struct tcphdr*)(pkt);
	hdr_len = tcph->doff * 4;

	/** remaining bytes were in tcp header? **/
	if (len < hdr_len)
		return 0;
	len -= hdr_len;
	return len;
}

static inline uint16_t parse_udp(const unsigned char* pkt, uint16_t len)
{
	// struct udphdr *udph;
	size_t header_len = sizeof(struct udphdr);

	/** remaining bytes were in udp header? **/
	if (len < header_len)
		return 0;

	// udph = (struct udphdr*)(pkt);

	len -= header_len;
	return len;
}

static inline uint16_t parse_ipv6(const unsigned char* pkt, uint16_t len)
{
	struct ip6_hdr *ip6h;

	size_t header_len = sizeof(struct ip6_hdr);

	if (len < header_len)
		/** remaining bytes we saw were ipv6 header **/
		return 0;

	ip6h = (struct ip6_hdr*)(pkt);


	ip6h->ip6_src = encrypt_ipv6(&ip6h->ip6_src);
	ip6h->ip6_dst = encrypt_ipv6(&ip6h->ip6_dst);

	len -= header_len;

	switch (ip6h->ip6_nxt) {
	case IPPROTO_TCP:
		return parse_tcp(pkt + header_len, len);

	case IPPROTO_UDP:
		return parse_udp(pkt + header_len, len);

	default:
		//TODO IPv6 extensions
		return len;
	}
}

static inline uint16_t parse_ipv4(const unsigned char* pkt, uint16_t len)
{
	struct iphdr *iph;
	uint16_t hdr_len;

	if (len < sizeof(struct iphdr))
		return 0;

	iph = (struct iphdr*)(pkt);
	hdr_len = iph->ihl * 4;

	iph->saddr = encrypt_ip(iph->saddr);
	iph->daddr = encrypt_ip(iph->daddr);

	/** remaining bytes we saw were ipv4 header? **/
	if (len < hdr_len)
		return 0;
	len -= hdr_len;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		return parse_tcp(pkt + hdr_len, len);

	case IPPROTO_UDP:
		return parse_udp(pkt + hdr_len, len);

	default:
		return len;
	}
}

static inline uint16_t parse_ethernet(const unsigned char* pkt, uint16_t len)
{
	/** remaining bytes we saw were ethernet header? **/
	if (len < ETHER_HDR_LEN)
		return 0;
	len -= ETHER_HDR_LEN;
	struct ether_header *hdr = (struct ether_header*)(pkt);

	switch (ntohs(hdr->ether_type)) {
	case ETHERTYPE_IP:
		return parse_ipv4(pkt + ETHER_HDR_LEN, len);

	case ETHERTYPE_IPV6:
		return parse_ipv6(pkt + ETHER_HDR_LEN, len);

	default:
		return 0;
	}
	;
}

uint16_t anonimize(uint16_t datalink, const struct pcap_pkthdr* hdr, const unsigned char* pkt)
{
	switch (datalink) {
	case DLT_EN10MB:
		return parse_ethernet(pkt, hdr->caplen);

	default:
		/** no headers found **/
		return hdr->caplen;
	}
}
