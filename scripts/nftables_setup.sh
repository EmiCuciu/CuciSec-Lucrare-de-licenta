#!/usr/bin/sudo bash

# Delete previous rules
iptables -F

iptables -X

nft flush ruleset

# main table
nft add table inet cucisec

# blacklist set   ->  every ip address from IPS logic from userspace will be automatically denied by network interface card (placa de retea)
nft add set inet cucisec blacklist { type ipv4_addr\; timeout 24h\; }

# input hook chain, maxim priority - then moved to netfilterqueue
nft add chain inet cucisec input { type filter hook input priority 0 \; }

# rule 1: instant drop for all ips from blacklist
nft add rule inet cucisec input ip saddr @blacklist counter drop

# rule 2: send rest of packets to NFQUEUE nr. 1
# TODO #### Do not forget to change ONLY PING PACKETS
nft add rule inet cucisec input icmp type echo-request counter queue num 1

echo "end of script"