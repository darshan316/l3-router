/* sim.h - tiny event-driven L2 medium that wires a router to model hosts so we
 * can watch a full ping (ARP resolution + ICMP echo/reply) cross the router. */
#ifndef SIM_H
#define SIM_H
int demo_route(void);     /* longest-prefix-match routing-table demo */
int demo_ping(void);      /* host A pings host B across the router       */
int demo_ttl(void);       /* TTL=1 packet -> router returns Time Exceeded */
#endif
