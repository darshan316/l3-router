/* ip.h - IPv4 address helpers, the Internet checksum, and on-wire headers.
 * Addresses are carried as host-order uint32_t internally and converted at the
 * wire boundary. Headers are packed structs in network byte order. */
#ifndef IP_H
#define IP_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define IPPROTO_ICMP_ 1

typedef uint32_t ipv4_t;                 /* host byte order */

bool  ip_parse(const char *s, ipv4_t *out);
char *ip_str(ipv4_t a, char *buf);       /* buf >= 16 */
ipv4_t ip_netmask(int prefix_len);
static inline bool ip_in_subnet(ipv4_t a, ipv4_t net, ipv4_t mask){
    return (a & mask) == (net & mask);
}

/* RFC 1071 one's-complement checksum over buf. */
uint16_t inet_checksum(const void *buf, size_t len);

#pragma pack(push,1)
typedef struct {
    uint8_t  ver_ihl;     /* version<<4 | IHL  */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t src;         /* network order */
    uint32_t dst;         /* network order */
} ip_hdr_t;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
    uint16_t id;
    uint16_t seq;
} icmp_echo_t;
#pragma pack(pop)

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0
#define ICMP_DEST_UNREACH 3
#define ICMP_TIME_EXCEEDED 11
#endif
