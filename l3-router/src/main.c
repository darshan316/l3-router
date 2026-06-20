/* main.c - driver for the L3 router.
 *   router route     longest-prefix-match routing-table demo
 *   router ping      hostA pings hostB across the router (ARP + ICMP)
 *   router ttl       TTL=1 -> router returns ICMP Time Exceeded
 *   router tap <if> <a.b.c.d/len> <mac> [<if> <cidr> <mac> ...]   live mode
 */
#include "sim.h"
#include "router.h"
#include "tap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <sys/select.h>
#include <unistd.h>
static int g_fds[MAX_IFACE];
static void tap_tx(void*ctx,int ifindex,const unsigned char*f,size_t n){
    (void)ctx; if(g_fds[ifindex]>=0) tap_write(g_fds[ifindex],f,n);
}
static int run_tap(int argc,char**argv){
    int groups=(argc-2)/3;
    if(groups<1||(argc-2)%3){ fprintf(stderr,"usage: tap <if> <a.b.c.d/len> <mac> ...\n"); return 1; }
    router_t R; router_init(&R,tap_tx,&R);
    int maxfd=0;
    for(int g=0;g<groups;g++){
        char*name=argv[2+g*3]; char*cidr=argv[3+g*3]; char*mac=argv[4+g*3];
        char ip[32]; int plen; if(sscanf(cidr,"%31[^/]/%d",ip,&plen)!=2){ fprintf(stderr,"bad cidr %s\n",cidr); return 1; }
        router_add_iface(&R,ip,plen,mac);
        char nm[32]; strncpy(nm,name,31); nm[31]=0;
        g_fds[g]=tap_open(nm);
        if(g_fds[g]<0){ perror("tap_open"); fprintf(stderr,"(needs root / CAP_NET_ADMIN)\n"); return 1; }
        printf("if%d %s %s mac %s (fd %d)\n",g,nm,cidr,mac,g_fds[g]);
        if(g_fds[g]>maxfd) maxfd=g_fds[g];
    }
    printf("routing... Ctrl-C to stop\n");
    for(;;){
        fd_set rs; FD_ZERO(&rs);
        for(int i=0;i<groups;i++) FD_SET(g_fds[i],&rs);
        if(select(maxfd+1,&rs,NULL,NULL,NULL)<0) break;
        for(int i=0;i<groups;i++) if(FD_ISSET(g_fds[i],&rs)){
            unsigned char b[ETH_MAX]; int r=tap_read(g_fds[i],b,sizeof b);
            if(r>0) router_rx(&R,i,b,(size_t)r);
        }
    }
    router_free(&R); return 0;
}
#endif

int main(int argc,char**argv){
    if(argc<2){ printf("usage: %s {route|ping|ttl|tap ...}\n",argv[0]); return 1; }
    if(!strcmp(argv[1],"route")) return demo_route();
    if(!strcmp(argv[1],"ping"))  return demo_ping();
    if(!strcmp(argv[1],"ttl"))   return demo_ttl();
#ifdef __linux__
    if(!strcmp(argv[1],"tap"))   return run_tap(argc,argv);
#endif
    fprintf(stderr,"unknown command '%s'\n",argv[1]); return 1;
}
