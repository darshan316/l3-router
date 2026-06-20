# l3-router an IPv4 router with longest-prefix match, ARP and ICMP

A Layer 3 router in C. It does what a router actually does on the wire:
verifies the IP header checksum, decrements TTL, looks up the destination by
longest-prefix match, resolves the next hop with ARP, rewrites the
Ethernet header and forwards and it speaks enough ICMP to answer pings and
return Time Exceeded / Destination Unreachable. It runs as a no-privilege
simulator (a router wired to two model hosts) and as a real router over Linux
TAP interfaces.

## Why this exists
Routing is the Layer 3 half of "Layer 2/3." The interesting parts of a router
aren't the packet format, they're (1) the LPM lookup that hardware does in a
TCAM here a bitwise trie and (2) the ARP + forwarding glue that turns a
routing decision into bytes on the next link. Both are implemented and tested.

## Forwarding path (one IP packet)

 frame ─▶ L2 filter (our MAC / bcast?)
        ─▶ ARP?  → reply for our IP, learn sender, release queued packets
        ─▶ IPv4: verify header checksum
             ├─ dst is us?  → ICMP echo  → echo reply
             └─ forward:
                  TTL<=1            → ICMP Time Exceeded, drop
                  LPM lookup miss   → ICMP Dest Unreachable, drop
                  TTL--, recompute checksum
                  next hop = route gateway (or dst if connected)
                  ARP known?  yes → rewrite L2, send
                              no  → queue packet, broadcast ARP request


## Layout
| file | what it is |
|------|------------|
| ip.[ch]     | IPv4 parse/format, netmasks, RFC 1071 checksum, packed headers |
| iptrie.[ch] | longest-prefix-match routing table (bitwise trie) |
| arp.[ch]    | ARP cache + request/reply build/parse (RFC 826) |
| eth.[ch]    | Ethernet II framing and MAC helpers |
| router.[ch] | interfaces, forwarding engine, ICMP, ARP-pending queue |
| sim.[ch]    | event-driven wire + model hosts for the ping demo |
| tap.[ch]    | Linux TAP backend for real interfaces |
| tests/      | unit tests for checksum, LPM and ARP |

## Build & test
sh
make          # builds ./router
make test     # runs unit tests (checksum / LPM / ARP 15 checks)


## Try it (no root needed)
sh
./router route   # routing table + LPM lookups (/25 beats /24, default route)
./router ping    # hostA pings hostB across the router,ARP runs on both legs
./router ttl     # a TTL=1 packet comes back as ICMP Time Exceeded (traceroute)

./router ping proves the whole datapath end to end:

hostA: ping 10.0.1.2 seq=1
hostA: reply from 10.0.1.2 seq=1  <-- ping success
Router rx=4 forwarded=2 arp_tx=2 ...


## Run it for real (Linux, root)
Give the router two TAP interfaces and route between two namespaces/hosts:
sh
sudo ./router tap tap0 10.0.0.1/24 02:00:00:00:00:01 \
                  tap1 10.0.1.1/24 02:00:00:00:00:02
# put a host on each subnet with its default route via the matching .1 and ping across


## Concepts demonstrated
IPv4 header parsing & checksum TTL decrement & ICMP Time Exceeded 
longest-prefix match in a trie  connected vs static vs default routes 
ARP resolution with a pending-packet queue  ICMP echo / destination-unreachable 
L2 rewrite on forward  TAP I/O.

## Deliberately out of scope
Dynamic routing protocols (OSPF/BGP), IP fragmentation/reassembly, and IPv6 —
left out to keep the forwarding core legible. The trie and route table are built
so a RIP/OSPF process could be layered on top.
