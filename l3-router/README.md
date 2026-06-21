# L3 IPv4 Router

A Layer 3 IPv4 router written in C. It performs the work a router does on the
wire: looking up the best route to a destination, resolving the next hop with
ARP, rewriting the packet, and forwarding it. It also answers pings and reports
errors using ICMP.

## Overview

A router connects different networks and forwards IP packets between them. This
project implements the forwarding path from scratch, including the route lookup,
address resolution, and error handling that a real router performs. It runs as a
simulator, with a router wired to two test hosts, and as a real router on Linux
TUN/TAP interfaces.

## What it implements

- Longest-prefix-match route lookup using a trie
- Connected, static, and default routes
- ARP to resolve the next hop, with a queue for packets waiting on a reply
- ICMP echo reply (ping), time exceeded, and destination unreachable
- TTL decrement and IP header checksum verification and update

## How it works

When a frame arrives, the router checks whether it is an ARP message or an IP
packet. ARP requests for the router's own addresses are answered, and the sender
is recorded. For an IP packet, the router verifies the header checksum. If the
packet is addressed to the router and is a ping, the router replies. Otherwise it
forwards the packet: it decrements the TTL, recomputes the checksum, looks up the
destination using longest-prefix match, finds the next hop, resolves that next
hop's hardware address with ARP, rewrites the Ethernet header, and sends the
packet out the correct interface. If the TTL has expired or no route exists, the
router returns the matching ICMP error message.

## Project structure

- ip: IPv4 address helpers, the Internet checksum, and packet headers
- iptrie: the routing table built as a longest-prefix-match trie
- arp: the ARP cache and message handling
- eth: Ethernet framing and address helpers
- router: the interfaces, the forwarding engine, and ICMP
- sim: a small simulator that wires the router to two hosts
- tap: connects the router to Linux TAP interfaces
- tests: unit tests for the checksum, route lookup, and ARP

## Building and running

Build the project and run the tests:

    make
    make test

Run the built-in demonstrations (no special privileges needed):

- ./router route : the routing table and example longest-prefix lookups
- ./router ping  : a host pings another host across the router
- ./router ttl   : a packet with an expired TTL returns an ICMP error

## Running with real traffic (Linux)

Give the router two TAP interfaces and route between two subnets:

    sudo ./router tap tap0 10.0.0.1/24 02:00:00:00:00:01 \
                       tap1 10.0.1.1/24 02:00:00:00:00:02

Place a host on each subnet with its default route set to the matching address,
then ping across the router.

## Concepts demonstrated

IPv4 header parsing and checksums, TTL handling, longest-prefix-match routing,
connected and static and default routes, ARP resolution, and ICMP.

## Limitations

To keep the forwarding path readable, this project does not implement dynamic
routing protocols, IP fragmentation, or IPv6.
