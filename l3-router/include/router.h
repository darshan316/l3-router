/* router.h - an IPv4 router: interfaces, ARP, longest-prefix-match forwarding,
 * and ICMP (echo reply, TTL-exceeded, destination-unreachable).
 *
 * router_rx() is the datapath for one received Ethernet frame:
 *   ARP  -> answer requests for our IPs, learn the sender.
 *   IPv4 -> if destined to us and it's an echo request, reply;
 *           otherwise verify checksum, decrement TTL, do an LPM route lookup,
 *           resolve the next hop with ARP, rewrite the L2 header and forward.
 * Packets that miss the ARP cache are queued while an ARP request goes out, and
 * released when the reply arrives -- just like a real router. */
#ifndef ROUTER_H
#define ROUTER_H
#include "eth.h"
#include "ip.h"
#include "arp.h"
#include "iptrie.h"

#define MAX_IFACE 8
#define MAX_PENDING 64

typedef struct { ipv4_t ip, mask; mac_t mac; bool up; } iface_t;

typedef void (*router_tx_fn)(void *ctx, int ifindex, const uint8_t *frame, size_t len);

typedef struct {
    uint8_t frame_ip[ETH_MAX]; size_t iplen;   /* the IP packet awaiting ARP */
    ipv4_t  next_hop; int ifindex; bool valid;
} pending_t;

typedef struct {
    iface_t  iface[MAX_IFACE]; int nif;
    arp_table_t arp;
    iptrie_t routes;
    pending_t pending[MAX_PENDING];
    router_tx_fn tx; void *ctx;
    unsigned long rx, forwarded, local, arp_tx, icmp_tx, dropped, ttl_drop, noroute;
} router_t;

void router_init(router_t *r, router_tx_fn tx, void *ctx);
void router_free(router_t *r);
int  router_add_iface(router_t *r, const char *ip, int prefix_len, const char *mac);
void router_add_route(router_t *r, const char *prefix, int len, const char *next_hop, int ifindex);
void router_rx(router_t *r, int ifindex, const uint8_t *frame, size_t len);
void router_stats(const router_t *r);
#endif
