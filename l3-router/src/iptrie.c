#include "iptrie.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void iptrie_init(iptrie_t *t){ t->root=calloc(1,sizeof(trie_node_t)); t->count=0; }
static void freerec(trie_node_t *n){ if(!n)return; freerec(n->child[0]); freerec(n->child[1]); free(n); }
void iptrie_free(iptrie_t *t){ freerec(t->root); t->root=NULL; t->count=0; }

static inline int bit_at(ipv4_t a,int i){ return (a >> (31-i)) & 1; }

void iptrie_add(iptrie_t *t, ipv4_t prefix,int len,ipv4_t nh,int ifx,int metric){
    prefix &= ip_netmask(len);
    trie_node_t *n=t->root;
    for(int i=0;i<len;i++){
        int b=bit_at(prefix,i);
        if(!n->child[b]) n->child[b]=calloc(1,sizeof(trie_node_t));
        n=n->child[b];
    }
    if(!n->has_route) t->count++;
    n->has_route=true;
    n->route=(route_t){ prefix,len,nh,ifx,metric };
}
const route_t *iptrie_lookup(const iptrie_t *t, ipv4_t dst){
    const trie_node_t *n=t->root; const route_t *best=NULL;
    for(int i=0;i<32 && n;i++){
        if(n->has_route) best=&n->route;       /* remember deepest match so far */
        n=n->child[bit_at(dst,i)];
    }
    if(n && n->has_route) best=&n->route;
    return best;
}
void iptrie_dump(const iptrie_t *t){
    char pb[16],nb[16];
    printf("  DEST/LEN           NEXT-HOP         IF   METRIC\n");
    /* simple DFS */
    trie_node_t *stack[64]; int sp=0; stack[sp++]=t->root;
    while(sp){
        trie_node_t *n=stack[--sp];
        if(!n) continue;
        if(n->has_route){
            route_t *r=&n->route;
            printf("  %-15s/%-2d  %-15s  %2d   %d\n", ip_str(r->prefix,pb), r->prefix_len,
                   r->next_hop? ip_str(r->next_hop,nb):"connected", r->ifindex, r->metric);
        }
        if(n->child[0]) stack[sp++]=n->child[0];
        if(n->child[1]) stack[sp++]=n->child[1];
    }
}
