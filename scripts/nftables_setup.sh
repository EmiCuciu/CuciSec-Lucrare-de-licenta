#!/usr/bin/sudo bash

# Delete previous rules
nft flush ruleset

# main table
nft add table inet cucisec




# blacklist set   ->  every ip_v4 and ip_v6 addresses from IPS logic from userspace will be automatically denied by network interface card (placa de retea)
# persists 24h
nft add set inet cucisec blacklist_v4 { type ipv4_addr\; timeout 24h\; }
nft add set inet cucisec blacklist_v6 { type ipv6_addr\; timeout 24h\; }




# dynamic sets  -> for flood trafic per ip, adds ip into set dynamic
nft add set inet cucisec flood_tracking_v4 { type ipv4_addr \; flags dynamic \; timeout 1m \; }
nft add set inet cucisec flood_tracking_v6 { type ipv6_addr \; flags dynamic \; timeout 1m \; }




# input hook = strict traficul care se opreste pe VM, in plus VM are un NAT care izoleaza ca sa aiba doar trafic intern
# ar trebui pus pe hook    forward ca sa simuleze real-life
# dar pentru teste lasam doar input momentan
# input hook chain, maxim priority - then moved to netfilterqueue
# policy accept - accept packet if it pass rules
nft add chain inet cucisec input { type filter hook input priority 0 \; policy accept \; }




# allow loopback
#nft add rule inet cucisec input iif lo accept

# allow ssh for local machine
nft add rule inet cucisec input tcp dport 22 accept





# instant drop for all ips from blacklist
# counter -> for graphics
nft add rule inet cucisec input ip saddr @blacklist_v4 counter drop
nft add rule inet cucisec input ip6 saddr @blacklist_v6 counter drop


#######################################################
# anti-flood / DoS

#ICMP FLOOD: max 5 packets/sec
# - burst 10 packets   ->  allow initial 10 packets spike,
nft add rule inet cucisec input ip protocol icmp limit rate over 5/second burst 10 packets counter drop
nft add rule inet cucisec input ip6 nexthdr icmpv6 limit rate over 5/second burst 10 packets counter drop


# TCP SYN FLOOD: max 20 new connections/sec per ip
# tcp flags syn -> only for new connections ,
# ip saddr != 0.0.0.0 -> ignores malformed packets (zero address)
nft add rule inet cucisec input tcp flags syn ip saddr != 0.0.0.0 update @flood_tracking_v4 { ip saddr limit rate over 20/second burst 40 packets } counter drop
nft add rule inet cucisec input tcp flags syn ip6 saddr != :: update @flood_tracking_v6 { ip6 saddr limit rate over 20/second burst 40 packets } counter drop


# UDP FLOOD: max 200 packets/sec per ip
nft add rule inet cucisec input ip protocol udp ip saddr != 0.0.0.0 update @flood_tracking_v4 { ip saddr limit rate over 200/second burst 250 packets } counter drop
nft add rule inet cucisec input ip6 nexthdr udp ip6 saddr != :: update @flood_tracking_v6 { ip6 saddr limit rate over 200/second burst 250 packets } counter drop


##########################################################






# rule 2: send rest of packets to NFQUEUE nr. 1
# TODO #### Do not forget to change ONLY PING PACKETS (ICMP)

nft add rule inet cucisec input ip protocol icmp counter queue num 1
nft add rule inet cucisec input ip6 nexthdr icmpv6 counter queue num 1

# HoneyPorts
nft add rule inet cucisec input tcp dport { 23, 2323, 3389, 4444, 9999 } counter queue num 1

echo "end of script"