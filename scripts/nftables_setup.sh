#!/usr/bin/sudo bash


nft -f - <<'EOF'

flush ruleset

table inet cucisec {

  set honey_ports {
    type inet_service
    elements = { 23, 2323, 3389, 4444, 9999 }
  }



  # blacklist set -> IPs banned by userspace IPS logic, dropped at NIC level
  # persists 24h
  set blacklist_v4 { type ipv4_addr; flags timeout; timeout 24h; }
  set blacklist_v6 { type ipv6_addr; flags timeout; timeout 24h; }



  # whitelist set -> trusted internal subnets, bypass kernel flood rate limits
  set whitelist_v4 { type ipv4_addr; flags interval; elements = { 127.0.0.0/8, 10.0.2.0/24, 10.0.3.0/24 }; }
  set whitelist_v6 { type ipv6_addr; flags interval; elements = { ::1 }; }



  # dynamic sets -> flood tracking per-IP, auto-expires after 1 minute
  set flood_v4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
  set flood_v6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; }



  # input chain — protects only the CuciSec VM itself (SSH access)
  chain input {

    type filter hook input priority 0; policy accept;



    iif "lo" accept
    tcp dport 22 ct state { new, established, related } accept
    ct state established,related accept
    ct state invalid drop



    # Management API (port 8000) — manage api only from localhost and LAN, block all others
    ip saddr @whitelist_v4 tcp dport 8000 ct state { new, established, related } accept
    tcp dport 8000 counter drop comment "mgmt_api_block"
  }



  # forward chain — intercepts all transit traffic
  chain forward {

    type filter hook forward priority 0; policy accept;

###########################################################################
    ##### LEVEL 1  -   instant drop for all IPs from blacklist

    ip saddr @blacklist_v4 counter drop comment "blacklist_drop"
    ip6 saddr @blacklist_v6 counter drop comment "blacklist_drop"
###########################################################################



###########################################################################
    ##### LEVEL 2 -     for DDOS (rand-source)

    # TCP SYN global — rand-source SYN flood
    tcp flags syn limit rate over 500/second burst 1000 packets counter drop comment "global_syn_flood"

    # UDP global —  rand-source UDP  flood
    ip protocol udp limit rate over 1000/second burst 2000 packets counter drop comment "global_udp_flood"
    ip6 nexthdr udp limit rate over 1000/second burst 2000 packets counter drop comment "global_udp_flood"

    # ICMP global — non-per-IP
    ip protocol icmp limit rate over 30/second burst 60 packets counter drop comment "global_icmp_flood"
    ip6 nexthdr icmpv6 limit rate over 30/second burst 60 packets counter drop comment "global_icmp_flood"
###########################################################################



###########################################################################
    ##### LEVEL 3 -     HTTP traffic — always sent to userspace for DPI
    tcp dport { 80, 8080, 8000, 8443 } counter queue num 1
###########################################################################



###########################################################################
    ##### LEVEL 4 -     allow already-established flows to pass without re-inspection
    ct state established,related counter accept

    # for malformed/invalid packets
    ct state invalid counter drop
###########################################################################



###########################################################################
    ###### LEVEL 5 -     whitelist bypass: trusted internal subnets skip flood rate limits
    ip saddr @whitelist_v4 counter queue num 1 comment "whitelist_bypass"
    ip6 saddr @whitelist_v6 counter queue num 1 comment "whitelist_bypass"
###########################################################################



###########################################################################
    ###### LEVEL 6 -     per-IP flood detection rate-limiting

    # ICMP FLOOD: max 5 packets/sec, burst 10
    ip protocol icmp limit rate over 5/second burst 10 packets counter drop comment "icmp_flood"
    ip6 nexthdr icmpv6 limit rate over 5/second burst 10 packets counter drop comment "icmp_flood"

    # TCP SYN FLOOD: max 20 new connections/sec per ip
    tcp flags syn ip saddr != 0.0.0.0 update @flood_v4 { ip saddr limit rate over 20/second burst 40 packets } counter drop comment "tcp_syn_flood"
    tcp flags syn ip6 saddr != :: update @flood_v6 { ip6 saddr limit rate over 20/second burst 40 packets } counter drop comment "tcp_syn_flood"

    # UDP FLOOD: max 200 packets/sec per ip
    ip protocol udp ip saddr != 0.0.0.0 update @flood_v4 { ip saddr limit rate over 200/second burst 250 packets } counter drop comment "udp_flood"
    ip6 nexthdr udp ip6 saddr != :: update @flood_v6 { ip6 saddr limit rate over 200/second burst 250 packets } counter drop comment "udp_flood"
###########################################################################



###########################################################################
    ##### LEVEL 7 -      honeyport sent to userspace for ban decision

    tcp dport @honey_ports counter queue num 1 comment "honeyport_drop"
###########################################################################

    counter queue num 1

  }

}

EOF