#include "sim.h"
#include "router.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/* ---------- a deliberately minimal host ---------- */
typedef struct {
    const char *name;
    ipv4_t ip, mask, gw;
    mac_t  mac;
    arp_table_t arp;
    void (*tx)(void*ctx,int ifindex,const uint8_t*f,size_t n);
    void *ctx;
    /* one-packet pending queue while we ARP for the next hop */
    uint8_t pend[ETH_MAX]; size_t pendlen; ipv4_t pend_nh; bool pending;
    int replies;
} host_t;

/* ---------- event-driven wire ---------- */
typedef struct { int kind; void *node; int ifindex; } ep_t;   /* kind 0=router 1=host */
typedef struct { ep_t a, b; } link_t;
static link_t g_links[8]; static int g_nlinks;
typedef struct { ep_t dst; uint8_t f[ETH_MAX]; size_t n; } evt_t;
static evt_t g_q[256]; static int g_qh, g_qt;

static void add_link(int ka,void*na,int ia,int kb,void*nb,int ib){
    g_links[g_nlinks++] = (link_t){ {ka,na,ia}, {kb,nb,ib} };
}
static bool ep_eq(ep_t x,int k,void*n,int i){ return x.kind==k&&x.node==n&&x.ifindex==i; }
static bool find_peer(int k,void*n,int i,ep_t*out){
    for(int j=0;j<g_nlinks;j++){
        if(ep_eq(g_links[j].a,k,n,i)){ *out=g_links[j].b; return true; }
        if(ep_eq(g_links[j].b,k,n,i)){ *out=g_links[j].a; return true; }
    }
    return false;
}
static void enqueue(ep_t dst,const uint8_t*f,size_t n){
    g_q[g_qt].dst=dst; memcpy(g_q[g_qt].f,f,n); g_q[g_qt].n=n; g_qt=(g_qt+1)&255;
}
static void emit(int k,void*node,int ifindex,const uint8_t*f,size_t n){
    ep_t peer; if(find_peer(k,node,ifindex,&peer)) enqueue(peer,f,n);
}
static void router_tx(void*ctx,int ifindex,const uint8_t*f,size_t n){ emit(0,ctx,ifindex,f,n); }
static void host_tx  (void*ctx,int ifindex,const uint8_t*f,size_t n){ emit(1,ctx,ifindex,f,n); }

/* ---------- host logic ---------- */
static void host_send_ip(host_t*h,ipv4_t dst,uint8_t proto,const uint8_t*l4,size_t l4len);

static void host_init(host_t*h,const char*name,const char*ip,int plen,const char*gw,const char*mac){
    memset(h,0,sizeof *h); h->name=name; ip_parse(ip,&h->ip); h->mask=ip_netmask(plen);
    ip_parse(gw,&h->gw); mac_parse(mac,&h->mac); arp_init(&h->arp); h->tx=host_tx; h->ctx=h;
}
static void host_arp_request(host_t*h,ipv4_t target){
    uint8_t ap[28]; size_t an=arp_build(ap,ARP_OP_REQUEST,h->mac,h->ip,(mac_t){{0}},target);
    uint8_t fr[ETH_MAX]; size_t n=eth_build(fr,mac_broadcast(),h->mac,ET_ARP,ap,an);
    h->tx(h->ctx,0,fr,n);
}
static void host_l2_send(host_t*h,ipv4_t nh,const uint8_t*ippkt,size_t iplen){
    mac_t dmac;
    if(arp_lookup(&h->arp,nh,&dmac)){
        uint8_t fr[ETH_MAX]; size_t n=eth_build(fr,dmac,h->mac,ET_IPV4,ippkt,iplen);
        h->tx(h->ctx,0,fr,n);
    } else {
        memcpy(h->pend,ippkt,iplen); h->pendlen=iplen; h->pend_nh=nh; h->pending=true;
        host_arp_request(h,nh);
    }
}
static void host_send_ip(host_t*h,ipv4_t dst,uint8_t proto,const uint8_t*l4,size_t l4len){
    uint8_t pkt[ETH_MAX]; ip_hdr_t*ih=(ip_hdr_t*)pkt; memset(ih,0,sizeof*ih);
    ih->ver_ihl=0x45; ih->tot_len=htons((uint16_t)(sizeof*ih+l4len)); ih->ttl=64;
    ih->proto=proto; ih->src=htonl(h->ip); ih->dst=htonl(dst);
    ih->check=htons(inet_checksum(ih,sizeof*ih));
    memcpy(pkt+sizeof*ih,l4,l4len);
    ipv4_t nh = ip_in_subnet(dst,h->ip,h->mask) ? dst : h->gw;   /* gateway if off-subnet */
    host_l2_send(h,nh,pkt,sizeof(ip_hdr_t)+l4len);
}
static void host_ping(host_t*h,const char*dst,uint16_t seq){
    ipv4_t d; ip_parse(dst,&d);
    uint8_t m[8]; icmp_echo_t*e=(icmp_echo_t*)m; memset(m,0,8);
    e->type=ICMP_ECHO_REQUEST; e->id=htons(0x1234); e->seq=htons(seq);
    e->check=htons(inet_checksum(m,8));
    char b[16]; printf("  %s: ping %s seq=%u\n",h->name,ip_str(d,b),seq);
    host_send_ip(h,d,IPPROTO_ICMP_,m,8);
}
static void host_rx(host_t*h,const uint8_t*f,size_t len){
    uint16_t et=eth_type(f);
    if(et==ET_ARP){
        arp_pkt_t a; if(!arp_parse(f+ETH_HLEN,len-ETH_HLEN,&a)) return;
        mac_t sha; memcpy(sha.addr,a.sha,6); arp_learn(&h->arp,arp_spa(&a),sha);
        if(a.op==ARP_OP_REQUEST && arp_tpa(&a)==h->ip){
            uint8_t ap[28]; size_t an=arp_build(ap,ARP_OP_REPLY,h->mac,h->ip,sha,arp_spa(&a));
            uint8_t fr[ETH_MAX]; size_t n=eth_build(fr,sha,h->mac,ET_ARP,ap,an); h->tx(h->ctx,0,fr,n);
        }
        if(h->pending && h->pend_nh==arp_spa(&a)){
            h->pending=false; host_l2_send(h,h->pend_nh,h->pend,h->pendlen);
        }
        return;
    }
    if(et!=ET_IPV4) return;
    const ip_hdr_t*ih=(const ip_hdr_t*)(f+ETH_HLEN);
    ipv4_t src=ntohl(ih->src);
    if(ntohl(ih->dst)!=h->ip || ih->proto!=IPPROTO_ICMP_) return;
    const icmp_echo_t*e=(const icmp_echo_t*)((const uint8_t*)ih+sizeof*ih);
    char b[16];
    if(e->type==ICMP_ECHO_REQUEST){
        uint8_t m[8]; memcpy(m,e,8); icmp_echo_t*r=(icmp_echo_t*)m;
        r->type=ICMP_ECHO_REPLY; r->check=0; r->check=htons(inet_checksum(m,8));
        host_send_ip(h,src,IPPROTO_ICMP_,m,8);
    } else if(e->type==ICMP_ECHO_REPLY){
        h->replies++;
        printf("  %s: reply from %s seq=%u  <-- ping success\n",h->name,ip_str(src,b),ntohs(e->seq));
    } else if(e->type==ICMP_TIME_EXCEEDED){
        printf("  %s: from %s: Time Exceeded (TTL=0 in transit)\n",h->name,ip_str(src,b));
    }
}

/* pump the event queue to quiescence */
static void run(router_t*R){
    int guard=0;
    while(g_qh!=g_qt && guard++<1000){
        evt_t e=g_q[g_qh]; g_qh=(g_qh+1)&255;
        if(e.dst.kind==0) router_rx((router_t*)e.dst.node,e.dst.ifindex,e.f,e.n);
        else              host_rx((host_t*)e.dst.node,e.f,e.n);
    }
    (void)R;
}
static void reset_wire(void){ g_nlinks=0; g_qh=g_qt=0; }

/* ---------- demos ---------- */
static void build(router_t*R,host_t*A,host_t*B){
    reset_wire();
    router_init(R,router_tx,R);
    router_add_iface(R,"10.0.0.1",24,"02:00:00:00:00:01"); /* if0 */
    router_add_iface(R,"10.0.1.1",24,"02:00:00:00:00:02"); /* if1 */
    host_init(A,"hostA","10.0.0.2",24,"10.0.0.1","02:00:00:00:0a:0a");
    host_init(B,"hostB","10.0.1.2",24,"10.0.1.1","02:00:00:00:0b:0b");
    add_link(0,R,0, 1,A,0);
    add_link(0,R,1, 1,B,0);
}

int demo_ping(void){
    printf("=== Ping across the router ===\n");
    printf("hostA 10.0.0.2/24  --[if0 10.0.0.1]  ROUTER  [if1 10.0.1.1]--  10.0.1.2/24 hostB\n");
    printf("Caches start empty, so this exercises ARP on BOTH segments + IP forwarding.\n\n");
    router_t R; host_t A,B; build(&R,&A,&B);
    host_ping(&A,"10.0.1.2",1);
    run(&R);
    printf("\nRouter "); router_stats(&R);
    printf("Result: hostA received %d echo reply(ies).\n", A.replies);
    router_free(&R);
    return A.replies?0:1;
}

int demo_ttl(void){
    printf("=== TTL handling ===\n");
    router_t R; host_t A,B; build(&R,&A,&B);
    /* warm the caches with a normal ping first */
    host_ping(&A,"10.0.1.2",1); run(&R);
    printf("\nNow hostA sends a packet with TTL=1; the router must drop it and\n");
    printf("return an ICMP Time Exceeded (this is what makes traceroute work).\n\n");
    /* craft TTL=1 echo to hostB */
    uint8_t pkt[ETH_MAX]; ip_hdr_t*ih=(ip_hdr_t*)pkt; memset(ih,0,sizeof*ih);
    uint8_t m[8]; icmp_echo_t*e=(icmp_echo_t*)m; memset(m,0,8);
    e->type=ICMP_ECHO_REQUEST; e->seq=htons(9); e->check=htons(inet_checksum(m,8));
    ih->ver_ihl=0x45; ih->tot_len=htons(sizeof*ih+8); ih->ttl=1; ih->proto=IPPROTO_ICMP_;
    ip_parse("10.0.0.2",&ih->src); ih->src=htonl(ih->src);
    ip_parse("10.0.1.2",&ih->dst); ih->dst=htonl(ih->dst);
    ih->check=htons(inet_checksum(ih,sizeof*ih)); memcpy(pkt+sizeof*ih,m,8);
    mac_t rmac; mac_parse("02:00:00:00:00:01",&rmac);
    uint8_t fr[ETH_MAX]; size_t n=eth_build(fr,rmac,A.mac,ET_IPV4,pkt,sizeof(ip_hdr_t)+8);
    enqueue((ep_t){0,&R,0},fr,n); run(&R);
    printf("\nRouter "); router_stats(&R);
    router_free(&R);
    return R.ttl_drop?0:1;
}

int demo_route(void){
    printf("=== Longest-prefix-match routing table ===\n");
    router_t R; router_init(&R,router_tx,&R);
    router_add_iface(&R,"10.0.0.1",24,"02:00:00:00:00:01");
    router_add_iface(&R,"10.0.1.1",24,"02:00:00:00:00:02");
    router_add_route(&R,"0.0.0.0",0,"10.0.0.254",0);    /* default route */
    router_add_route(&R,"10.0.0.128",25,"10.0.1.9",1);  /* more specific than /24 */
    router_add_route(&R,"192.168.5.0",24,"10.0.1.9",1);
    printf("Routing table:\n"); iptrie_dump(&R.routes);
    struct { const char*ip; const char*expect; } cases[]={
        {"10.0.0.5","connected (/24)"},
        {"10.0.0.200","via 10.0.1.9 (/25 wins over /24)"},
        {"192.168.5.7","via 10.0.1.9 (/24)"},
        {"8.8.8.8","via 10.0.0.254 (default /0)"},
    };
    printf("\nLookups (longest prefix wins):\n");
    for(size_t i=0;i<sizeof cases/sizeof cases[0];i++){
        ipv4_t d; ip_parse(cases[i].ip,&d);
        const route_t*rt=iptrie_lookup(&R.routes,d);
        char pb[16],nb[16];
        printf("  %-12s -> %s/%d %-16s  [expected: %s]\n",cases[i].ip,
               ip_str(rt->prefix,pb),rt->prefix_len,
               rt->next_hop?ip_str(rt->next_hop,nb):"connected",cases[i].expect);
    }
    router_free(&R);
    return 0;
}
