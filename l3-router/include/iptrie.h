/* iptrie.h - longest-prefix-match routing table as a binary (bitwise) trie.
 *
 * Every route is a prefix (e.g. 10.0.1.0/24). Lookup walks the destination
 * address bit by bit from the MSB, remembering the deepest prefix node that
 * carried a route -- that is, by construction, the longest match. This is the
 * textbook software analogue of the TCAM lookup in router hardware. */
#ifndef IPTRIE_H
#define IPTRIE_H
#include "ip.h"

typedef struct {
    ipv4_t prefix;
    int    prefix_len;
    ipv4_t next_hop;     /* 0 => directly connected (use packet dst) */
    int    ifindex;
    int    metric;
} route_t;

typedef struct trie_node {
    struct trie_node *child[2];
    route_t  route;
    bool     has_route;
} trie_node_t;

typedef struct { trie_node_t *root; int count; } iptrie_t;

void  iptrie_init(iptrie_t *t);
void  iptrie_free(iptrie_t *t);
/* Insert/replace a route. */
void  iptrie_add(iptrie_t *t, ipv4_t prefix, int prefix_len,
                 ipv4_t next_hop, int ifindex, int metric);
/* Longest-prefix match. Returns route or NULL if unreachable. */
const route_t *iptrie_lookup(const iptrie_t *t, ipv4_t dst);
void  iptrie_dump(const iptrie_t *t);
#endif
