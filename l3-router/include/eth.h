/* eth.h - minimal Ethernet II framing for the router's interfaces. */
#ifndef ETH_H
#define ETH_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_MAX 1600
#define ET_IPV4 0x0800
#define ET_ARP  0x0806
typedef struct { uint8_t addr[ETH_ALEN]; } mac_t;
bool  mac_parse(const char*s, mac_t*m);
char *mac_str(mac_t m, char*buf);          /* >=18 */
bool  mac_equal(mac_t a, mac_t b);
bool  mac_is_bcast(mac_t m);
mac_t mac_broadcast(void);
mac_t eth_dst(const uint8_t*f);
mac_t eth_src(const uint8_t*f);
uint16_t eth_type(const uint8_t*f);
size_t eth_build(uint8_t*out, mac_t dst, mac_t src, uint16_t type,
                 const uint8_t*payload, size_t plen);
#endif
