#include "router.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void router_init(router_t *r, router_tx_fn tx, void *ctx){
    memset(r,0,sizeof(*r));
    r->tx=tx; r->ctx=ctx;
    arp_init(&r->arp);
    iptrie_init(&r->routes);
}
void router_free(router_t *r){ iptrie_free(&r->routes); }

int router_add_iface(router_t *r, const char *ip, int plen, const char *mac){
    int i=r->nif++;
    ip_parse(ip,&r->iface[i].ip);
    r->iface[i].mask=ip_netmask(plen);
    mac_parse(mac,&r->iface[i].mac);
    r->iface[i].up=true;
    /* directly-connected route for this interface's subnet */
    iptrie_add(&r->routes, r->iface[i].ip & r->iface[i].mask, plen, 0, i, 0);
    return i;
}
void router_add_route(router_t *r, const char *prefix, int len, const char *nh, int ifx){
    ipv4_t p,g=0; ip_parse(prefix,&p); if(nh) ip_parse(nh,&g);
    iptrie_add(&r->routes,p,len,g,ifx,1);
}
static int iface_for_ip(const router_t *r, ipv4_t ip){
    for(int i=0;i<r->nif;i++) if(r->iface[i].ip==ip) return i;
    return -1;
}

/* Resolve next_hop to a MAC and ship the IP packet out ifindex. If the MAC is
 * unknown, queue the packet and emit an ARP request. */
static void route_and_send(router_t *r, const uint8_t *ippkt, size_t iplen, ipv4_t dst){
    const route_t *rt=iptrie_lookup(&r->routes,dst);
    if(!rt){ r->noroute++; r->dropped++; return; }
    ipv4_t nh = rt->next_hop ? rt->next_hop : dst;
    int oif = rt->ifindex;
    mac_t dmac;
    if(arp_lookup(&r->arp,nh,&dmac)){
        uint8_t fr[ETH_MAX];
        size_t n=eth_build(fr,dmac,r->iface[oif].mac,ET_IPV4,ippkt,iplen);
        r->tx(r->ctx,oif,fr,n);
        r->forwarded++;
        return;
    }
    /* queue + ARP request */
    for(int i=0;i<MAX_PENDING;i++) if(!r->pending[i].valid){
        memcpy(r->pending[i].frame_ip,ippkt,iplen);
        r->pending[i].iplen=iplen; r->pending[i].next_hop=nh; r->pending[i].ifindex=oif;
        r->pending[i].valid=true; break;
    }
    uint8_t ap[28]; size_t an=arp_build(ap,ARP_OP_REQUEST,r->iface[oif].mac,r->iface[oif].ip,
                                        (mac_t){{0,0,0,0,0,0}}, nh);
    uint8_t fr[ETH_MAX]; size_t n=eth_build(fr,mac_broadcast(),r->iface[oif].mac,ET_ARP,ap,an);
    r->tx(r->ctx,oif,fr,n); r->arp_tx++;
}
static void flush_pending(router_t *r, ipv4_t ip, mac_t mac){
    for(int i=0;i<MAX_PENDING;i++){
        if(!r->pending[i].valid || r->pending[i].next_hop!=ip) continue;
        uint8_t fr[ETH_MAX];
        size_t n=eth_build(fr,mac,r->iface[r->pending[i].ifindex].mac,ET_IPV4,
                           r->pending[i].frame_ip,r->pending[i].iplen);
        r->tx(r->ctx,r->pending[i].ifindex,fr,n); r->forwarded++;
        r->pending[i].valid=false;
    }
}

/* Build IP header + L4 payload and route it (used for ICMP we originate). */
static void ip_emit(router_t *r, ipv4_t src, ipv4_t dst, uint8_t proto,
                    const uint8_t *l4, size_t l4len){
    uint8_t pkt[ETH_MAX]; ip_hdr_t *h=(ip_hdr_t*)pkt;
    memset(h,0,sizeof *h);
    h->ver_ihl=0x45; h->tot_len=htons((uint16_t)(sizeof(ip_hdr_t)+l4len));
    h->ttl=64; h->proto=proto; h->src=htonl(src); h->dst=htonl(dst);
    h->check=0; h->check=htons(inet_checksum(h,sizeof *h));
    memcpy(pkt+sizeof *h,l4,l4len);
    route_and_send(r,pkt,sizeof(ip_hdr_t)+l4len,dst);
}
static void send_icmp_error(router_t *r,int in,ipv4_t to,const uint8_t *orig,size_t origlen,
                            uint8_t type,uint8_t code){
    uint8_t msg[8+sizeof(ip_hdr_t)+8]; memset(msg,0,8);
    msg[0]=type; msg[1]=code;
    size_t quote = origlen < sizeof(ip_hdr_t)+8 ? origlen : sizeof(ip_hdr_t)+8;
    memcpy(msg+8,orig,quote);
    uint16_t c=inet_checksum(msg,8+quote); msg[2]=c>>8; msg[3]=c&0xff;
    ip_emit(r,r->iface[in].ip,to,IPPROTO_ICMP_,msg,8+quote); r->icmp_tx++;
}

static void handle_arp(router_t *r,int in,const uint8_t *payload,size_t len){
    arp_pkt_t a; if(!arp_parse(payload,len,&a)) return;
    ipv4_t spa=arp_spa(&a), tpa=arp_tpa(&a);
    mac_t sha; memcpy(sha.addr,a.sha,6);
    arp_learn(&r->arp,spa,sha);
    flush_pending(r,spa,sha);
    if(a.op==ARP_OP_REQUEST && tpa==r->iface[in].ip){
        uint8_t ap[28]; size_t an=arp_build(ap,ARP_OP_REPLY,r->iface[in].mac,r->iface[in].ip,sha,spa);
        uint8_t fr[ETH_MAX]; size_t n=eth_build(fr,sha,r->iface[in].mac,ET_ARP,ap,an);
        r->tx(r->ctx,in,fr,n); r->arp_tx++;
    }
}

static void handle_ip(router_t *r,int in,const uint8_t *frame,size_t len){
    if(len < ETH_HLEN+(int)sizeof(ip_hdr_t)) { r->dropped++; return; }
    const ip_hdr_t *h=(const ip_hdr_t*)(frame+ETH_HLEN);
    size_t iplen=len-ETH_HLEN;
    if(inet_checksum(h,sizeof *h)!=0){ r->dropped++; return; }   /* bad header checksum */
    ipv4_t src=ntohl(h->src), dst=ntohl(h->dst);

    if(iface_for_ip(r,dst)>=0){                 /* destined to the router itself */
        r->local++;
        if(h->proto==IPPROTO_ICMP_ && iplen>=sizeof(ip_hdr_t)+sizeof(icmp_echo_t)){
            const icmp_echo_t *q=(const icmp_echo_t*)((const uint8_t*)h+sizeof *h);
            if(q->type==ICMP_ECHO_REQUEST){
                size_t l4=iplen-sizeof(ip_hdr_t);
                uint8_t reply[ETH_MAX]; memcpy(reply,q,l4);
                ((icmp_echo_t*)reply)->type=ICMP_ECHO_REPLY;
                ((icmp_echo_t*)reply)->check=0;
                uint16_t c=inet_checksum(reply,l4); reply[2]=c>>8; reply[3]=c&0xff;
                ip_emit(r,dst,src,IPPROTO_ICMP_,reply,l4); r->icmp_tx++;
            }
        }
        return;
    }
    /* forwarding path */
    if(h->ttl<=1){ send_icmp_error(r,in,src,(const uint8_t*)h,iplen,ICMP_TIME_EXCEEDED,0);
                   r->ttl_drop++; r->dropped++; return; }
    if(!iptrie_lookup(&r->routes,dst)){
        send_icmp_error(r,in,src,(const uint8_t*)h,iplen,ICMP_DEST_UNREACH,0);
        r->noroute++; r->dropped++; return;
    }
    /* mutate a working copy: TTL-- and recompute checksum */
    uint8_t pkt[ETH_MAX]; memcpy(pkt,h,iplen);
    ip_hdr_t *nh=(ip_hdr_t*)pkt; nh->ttl--; nh->check=0;
    nh->check=htons(inet_checksum(nh,sizeof *nh));
    route_and_send(r,pkt,iplen,dst);
}

void router_rx(router_t *r,int in,const uint8_t *frame,size_t len){
    if(in<0||in>=r->nif||len<ETH_HLEN) return;
    r->rx++;
    mac_t d=eth_dst(frame);
    /* accept frames addressed to our interface MAC or broadcast */
    if(!mac_is_bcast(d) && !mac_equal(d,r->iface[in].mac)){ r->dropped++; return; }
    uint16_t et=eth_type(frame);
    if(et==ET_ARP)      handle_arp(r,in,frame+ETH_HLEN,len-ETH_HLEN);
    else if(et==ET_IPV4) handle_ip(r,in,frame,len);
    else r->dropped++;
}
void router_stats(const router_t *r){
    printf("rx=%lu forwarded=%lu local=%lu arp_tx=%lu icmp_tx=%lu ttl_drop=%lu noroute=%lu dropped=%lu\n",
           r->rx,r->forwarded,r->local,r->arp_tx,r->icmp_tx,r->ttl_drop,r->noroute,r->dropped);
}
