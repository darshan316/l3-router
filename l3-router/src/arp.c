#include "arp.h"
#include <string.h>
#include <arpa/inet.h>
void arp_init(arp_table_t*t){ t->n=0; }
void arp_learn(arp_table_t*t, ipv4_t ip, mac_t mac){
    for(int i=0;i<t->n;i++) if(t->e[i].ip==ip){ t->e[i].mac=mac; t->e[i].valid=true; return; }
    if(t->n<ARP_MAX){ t->e[t->n++]=(arp_entry_t){ip,mac,true}; }
}
bool arp_lookup(const arp_table_t*t, ipv4_t ip, mac_t*out){
    for(int i=0;i<t->n;i++) if(t->e[i].ip==ip && t->e[i].valid){ if(out)*out=t->e[i].mac; return true; }
    return false;
}
static void put_ip(uint8_t*p, ipv4_t a){ p[0]=a>>24; p[1]=a>>16; p[2]=a>>8; p[3]=a; }
static ipv4_t get_ip(const uint8_t*p){ return (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]; }
size_t arp_build(uint8_t*o,uint16_t op,mac_t sha,ipv4_t spa,mac_t tha,ipv4_t tpa){
    arp_pkt_t a; memset(&a,0,sizeof a);
    a.htype=htons(1); a.ptype=htons(0x0800); a.hlen=6; a.plen=4; a.op=htons(op);
    memcpy(a.sha,sha.addr,6); put_ip(a.spa,spa);
    memcpy(a.tha,tha.addr,6); put_ip(a.tpa,tpa);
    memcpy(o,&a,sizeof a); return sizeof a;
}
bool arp_parse(const uint8_t*p,size_t len,arp_pkt_t*out){
    if(len<28) return false;
    memcpy(out,p,28);
    out->htype=ntohs(out->htype); out->ptype=ntohs(out->ptype); out->op=ntohs(out->op);
    return true;
}
ipv4_t arp_spa(const arp_pkt_t*a){ return get_ip(a->spa); }
ipv4_t arp_tpa(const arp_pkt_t*a){ return get_ip(a->tpa); }
