/* arp.h - ARP cache + packet build/parse (RFC 826, Ethernet/IPv4). */
#ifndef ARP_H
#define ARP_H
#include "eth.h"
#include "ip.h"

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2
#define ARP_MAX 256

typedef struct { ipv4_t ip; mac_t mac; bool valid; } arp_entry_t;
typedef struct { arp_entry_t e[ARP_MAX]; int n; } arp_table_t;

void  arp_init(arp_table_t*t);
void  arp_learn(arp_table_t*t, ipv4_t ip, mac_t mac);
bool  arp_lookup(const arp_table_t*t, ipv4_t ip, mac_t*out);

#pragma pack(push,1)
typedef struct {
    uint16_t htype, ptype;
    uint8_t  hlen, plen;
    uint16_t op;
    uint8_t  sha[6]; uint8_t spa[4];
    uint8_t  tha[6]; uint8_t tpa[4];
} arp_pkt_t;
#pragma pack(pop)

/* Build an ARP request/reply payload (28 bytes) into out. */
size_t arp_build(uint8_t*out, uint16_t op, mac_t sha, ipv4_t spa, mac_t tha, ipv4_t tpa);
bool   arp_parse(const uint8_t*payload, size_t len, arp_pkt_t*out);
ipv4_t arp_spa(const arp_pkt_t*a);
ipv4_t arp_tpa(const arp_pkt_t*a);
#endif
