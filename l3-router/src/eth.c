#include "eth.h"
#include <stdio.h>
#include <string.h>
static uint16_t rd16(const uint8_t*p){ return (uint16_t)((p[0]<<8)|p[1]); }
bool mac_parse(const char*s, mac_t*m){
    unsigned v[6];
    if(sscanf(s,"%x:%x:%x:%x:%x:%x",v,v+1,v+2,v+3,v+4,v+5)!=6) return false;
    for(int i=0;i<6;i++) m->addr[i]=(uint8_t)v[i];
    return true;
}
char *mac_str(mac_t m,char*b){ sprintf(b,"%02x:%02x:%02x:%02x:%02x:%02x",
    m.addr[0],m.addr[1],m.addr[2],m.addr[3],m.addr[4],m.addr[5]); return b; }
bool mac_equal(mac_t a,mac_t b){ return memcmp(a.addr,b.addr,6)==0; }
bool mac_is_bcast(mac_t m){ for(int i=0;i<6;i++) if(m.addr[i]!=0xff) return false; return true; }
mac_t mac_broadcast(void){ mac_t m; memset(m.addr,0xff,6); return m; }
mac_t eth_dst(const uint8_t*f){ mac_t m; memcpy(m.addr,f,6); return m; }
mac_t eth_src(const uint8_t*f){ mac_t m; memcpy(m.addr,f+6,6); return m; }
uint16_t eth_type(const uint8_t*f){ return rd16(f+12); }
size_t eth_build(uint8_t*o,mac_t d,mac_t s,uint16_t t,const uint8_t*p,size_t pl){
    memcpy(o,d.addr,6); memcpy(o+6,s.addr,6); o[12]=t>>8; o[13]=t&0xff;
    if(p&&pl) memcpy(o+14,p,pl);
    return ETH_HLEN+pl;
}
