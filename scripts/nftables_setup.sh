#!/bin/bash

nft -f - <<'EOF'

flush ruleset

table inet cucisec {

# Trap ports — any connection attempt here is treated as hostile
  set honey_ports {
    type inet_service
    elements = { 23, 2323, 3389, 4444, 9999 }
  }


# Permanent ban list — populated by userspace IPS, dropped at NIC level
  set blacklist_v4 { type ipv4_addr; }
  set blacklist_v6 { type ipv6_addr; }


# Trusted subnets — bypass all flood rate limits
  set whitelist_v4 { type ipv4_addr; flags interval; elements = { 127.0.0.0/8, 10.0.2.0/24, 10.0.3.0/24 }; }
  set whitelist_v6 { type ipv6_addr; flags interval; elements = { ::1 }; }


# Per-source flood tracking, auto-expires after 1 minute
  set flood_v4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
  set flood_v6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; }


# Per-destination flood tracking (defeats --rand-source attacks)
  set flood_dst_syn_v4  { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
  set flood_dst_syn_v6  { type ipv6_addr; flags dynamic, timeout; timeout 1m; }
  set flood_dst_udp_v4  { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
  set flood_dst_udp_v6  { type ipv6_addr; flags dynamic, timeout; timeout 1m; }
  set flood_dst_icmp_v4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
  set flood_dst_icmp_v6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; }



# input chain — protects the CuciSec host itself (SSH, management API)
  chain input {
    type filter hook input priority 0; policy accept;


    iif "lo"     accept
    tcp dport 22 ct state { new, established, related } accept
    ct state established,related accept
    ct state invalid drop


# Management API accessible only from trusted subnets
    ip saddr @whitelist_v4 tcp dport 8000 ct state { new, established, related } accept
    tcp dport 8000 counter drop comment "mgmt_api_block"
  }



# forward chain — all transit traffic between WAN and LAN
  chain forward {
    type filter hook forward priority 0; policy accept;

    ct state invalid drop


# ── Blacklist: instant drop for banned IPs
    ip  saddr @blacklist_v4 counter drop comment "blacklist_drop"
    ip6 saddr @blacklist_v6 counter drop comment "blacklist_drop"


# ── Whitelist: trusted subnets bypass all rate limits and NFQUEUE
    ip  saddr @whitelist_v4 accept
    ip6 saddr @whitelist_v6 accept


# ── Global rate limits — defeat rand-source volumetric DDoS
    tcp flags syn               limit rate over  50/second burst 100 packets counter drop comment "global_syn_flood"
    ip  protocol udp            limit rate over 100/second burst 200 packets counter drop comment "global_udp_flood"
    ip6 nexthdr  udp            limit rate over 100/second burst 200 packets counter drop comment "global_udp_flood"
    ip  protocol icmp           limit rate over  10/second burst  20 packets counter drop comment "global_icmp_flood"
    ip6 nexthdr  icmpv6         limit rate over  10/second burst  20 packets counter drop comment "global_icmp_flood"


# ── Per-destination rate limits — defeat fixed-source floods toward a single host
    tcp flags syn ip  daddr != 0.0.0.0 update @flood_dst_syn_v4  { ip  daddr limit rate over 30/second burst  50 packets } counter drop comment "dst_syn_flood"
    tcp flags syn ip6 daddr != ::      update @flood_dst_syn_v6  { ip6 daddr limit rate over 30/second burst  50 packets } counter drop comment "dst_syn_flood"
    ip  protocol udp ip  daddr != 0.0.0.0 update @flood_dst_udp_v4  { ip  daddr limit rate over  80/second burst 150 packets } counter drop comment "dst_udp_flood"
    ip6 nexthdr  udp ip6 daddr != ::      update @flood_dst_udp_v6  { ip6 daddr limit rate over  80/second burst 150 packets } counter drop comment "dst_udp_flood"
    ip  protocol icmp   ip  daddr != 0.0.0.0 update @flood_dst_icmp_v4 { ip  daddr limit rate over 8/second burst 15 packets } counter drop comment "dst_icmp_flood"
    ip6 nexthdr  icmpv6 ip6 daddr != ::      update @flood_dst_icmp_v6 { ip6 daddr limit rate over 8/second burst 15 packets } counter drop comment "dst_icmp_flood"


# ── HTTP — forwarded to userspace for DPI inspection
    tcp dport { 80, 8080, 8000, 8443 } counter queue num 1


# ── Per-source rate limits — detect sustained single-source floods
    ip  protocol icmp   limit rate over  5/second burst  10 packets counter drop comment "icmp_flood"
    ip6 nexthdr  icmpv6 limit rate over  5/second burst  10 packets counter drop comment "icmp_flood"
    tcp flags syn ip  saddr != 0.0.0.0 update @flood_v4 { ip  saddr limit rate over  20/second burst  40 packets } counter drop comment "tcp_syn_flood"
    tcp flags syn ip6 saddr != ::      update @flood_v6 { ip6 saddr limit rate over  20/second burst  40 packets } counter drop comment "tcp_syn_flood"
    ip  protocol udp ip  saddr != 0.0.0.0 update @flood_v4 { ip  saddr limit rate over 200/second burst 250 packets } counter drop comment "udp_flood"
    ip6 nexthdr  udp ip6 saddr != ::      update @flood_v6 { ip6 saddr limit rate over 200/second burst 250 packets } counter drop comment "udp_flood"


# ── Honeyports — forwarded to userspace for ban decision
    tcp dport @honey_ports counter queue num 1 comment "honeyport_drop"


# ── Default: all remaining traffic goes to userspace
    counter queue num 1
  }

}

EOF