#include "tap.h"
#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int tap_open(char *name){
    int fd=open("/dev/net/tun",O_RDWR);
    if(fd<0) return -1;
    struct ifreq ifr; memset(&ifr,0,sizeof(ifr));
    ifr.ifr_flags=IFF_TAP|IFF_NO_PI;            /* TAP = Ethernet frames, no header */
    if(name&&*name) strncpy(ifr.ifr_name,name,IFNAMSIZ-1);
    if(ioctl(fd,TUNSETIFF,&ifr)<0){ close(fd); return -1; }
    if(name) strcpy(name,ifr.ifr_name);
    return fd;
}
int tap_read(int fd,unsigned char *b,size_t c){ return (int)read(fd,b,c); }
int tap_write(int fd,const unsigned char *b,size_t l){ return (int)write(fd,b,l); }
#else
int tap_open(char *n){ (void)n; return -1; }       /* TAP is Linux-only */
int tap_read(int fd,unsigned char *b,size_t c){ (void)fd;(void)b;(void)c; return -1; }
int tap_write(int fd,const unsigned char *b,size_t l){ (void)fd;(void)b;(void)l; return -1; }
#endif
