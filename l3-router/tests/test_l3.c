/* Dependency-free unit tests for the router building blocks. */
#include "ip.h"
#include "iptrie.h"
#include "arp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int pass=0, fail=0;
#define CHECK(c,m) do{ if(c)pass++; else{fail++; printf("  FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__);} }while(0)
static ipv4_t IP(const char*s){ ipv4_t a; ip_parse(s,&a); return a; }

static void test_ip(void){
    printf("[ip]\n");
    char b[16];
    CHECK(IP("10.0.1.2")==0x0a000102,"parse dotted quad");
    CHECK(strcmp(ip_str(IP("192.168.1.1"),b),"192.168.1.1")==0,"format round-trips");
    CHECK(ip_netmask(24)==0xffffff00,"/24 netmask");
    CHECK(ip_netmask(0)==0,"/0 netmask");
    CHECK(ip_in_subnet(IP("10.0.0.55"),IP("10.0.0.0"),ip_netmask(24)),"addr in subnet");
    CHECK(!ip_in_subnet(IP("10.0.1.55"),IP("10.0.0.0"),ip_netmask(24)),"addr not in subnet");
    /* checksum: a valid IPv4 header must sum to zero */
    ip_hdr_t h; memset(&h,0,sizeof h);
    h.ver_ihl=0x45; h.tot_len=htons(20); h.ttl=64; h.proto=1;
    h.src=htonl(IP("10.0.0.1")); h.dst=htonl(IP("10.0.1.2"));
    h.check=htons(inet_checksum(&h,sizeof h));
    CHECK(inet_checksum(&h,sizeof h)==0,"valid header checksum verifies to 0");
}
static void test_lpm(void){
    printf("[lpm]\n");
    iptrie_t t; iptrie_init(&t);
    iptrie_add(&t,IP("0.0.0.0"),0,IP("10.0.0.254"),0,1);   /* default */
    iptrie_add(&t,IP("10.0.0.0"),24,0,0,0);                /* connected */
    iptrie_add(&t,IP("10.0.0.128"),25,IP("10.0.1.9"),1,1); /* more specific */
    const route_t*r;
    r=iptrie_lookup(&t,IP("10.0.0.5"));   CHECK(r&&r->prefix_len==24,"/24 connected match");
    r=iptrie_lookup(&t,IP("10.0.0.200")); CHECK(r&&r->prefix_len==25,"/25 beats /24 (longest prefix)");
    r=iptrie_lookup(&t,IP("8.8.8.8"));    CHECK(r&&r->prefix_len==0,"falls back to default route");
    r=iptrie_lookup(&t,IP("10.0.0.200")); CHECK(r&&r->next_hop==IP("10.0.1.9"),"correct next hop");
    iptrie_free(&t);
}
static void test_arp(void){
    printf("[arp]\n");
    arp_table_t t; arp_init(&t); mac_t m,out;
    mac_parse("aa:bb:cc:dd:ee:ff",&m);
    CHECK(!arp_lookup(&t,IP("10.0.0.2"),&out),"miss before learn");
    arp_learn(&t,IP("10.0.0.2"),m);
    CHECK(arp_lookup(&t,IP("10.0.0.2"),&out)&&mac_equal(out,m),"hit after learn");
    /* build/parse a request round-trips the addresses */
    uint8_t buf[28]; mac_parse("11:22:33:44:55:66",&m);
    arp_build(buf,ARP_OP_REQUEST,m,IP("10.0.0.1"),mac_broadcast(),IP("10.0.0.9"));
    arp_pkt_t a; CHECK(arp_parse(buf,28,&a),"parse ok");
    CHECK(a.op==ARP_OP_REQUEST&&arp_spa(&a)==IP("10.0.0.1")&&arp_tpa(&a)==IP("10.0.0.9"),"fields round-trip");
}
int main(void){
    test_ip(); test_lpm(); test_arp();
    printf("\n%d passed, %d failed\n",pass,fail);
    return fail?1:0;
}
