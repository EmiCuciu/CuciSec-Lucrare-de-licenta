#!/usr/bin/sudo bash


nft -f - <<'EOF'

flush ruleset

table inet cucisec {

  set honey_ports {
    type inet_service
    elements = { 23, 2323, 3389, 4444, 9999 }
  }

  # blacklist set   ->  every ip_v4 and ip_v6 addresses from IPS logic from userspace will be automatically denied by network interface card (placa de retea)
  # persists 24h
  set blacklist_v4 { type ipv4_addr; flags timeout; timeout 24h; }
  set blacklist_v6 { type ipv6_addr; flags timeout; timeout 24h; }


  # dynamic sets  -> for flood trafic per ip, adds ip into set dynamic
  set flood_v4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
  set flood_v6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; }



  # input hook = strict traficul care se opreste pe VM, in plus VM are un NAT care izoleaza ca sa aiba doar trafic intern
  # ar trebui pus pe hook    forward ca sa simuleze real-life
  # dar pentru teste lasam doar input momentan
  # input hook chain, maxim priority - then moved to netfilterqueue
  # policy accept - accept packet if it pass rules
  chain input {

    type filter hook input priority 0; policy accept;

    # allow loopback
#    iif "lo" accept

    # allow ssh for local machine
    tcp dport 22 ct state new accept
    tcp dport 22 ct state established,related accept

    # for malformed/invalid packets
    ct state invalid counter drop



    # instant drop for all ips from blacklist
    ip saddr @blacklist_v4 counter drop comment "blacklist_drop"
    ip6 saddr @blacklist_v6 counter drop comment "blacklist_drop"



    #######################################################
    # anti-flood / DoS
    #ICMP FLOOD: max 5 packets/sec
    # - burst 10 packets   ->  allow initial 10 packets spike,
    ip protocol icmp limit rate over 5/second burst 10 packets counter drop comment "icmp_flood"
    ip6 nexthdr icmpv6 limit rate over 5/second burst 10 packets counter drop comment "icmp_flood"


    # TCP SYN FLOOD: max 20 new connections/sec per ip
    # tcp flags syn -> only for new connections ,
    # ip saddr != 0.0.0.0 -> ignores malformed packets (zero address)
    tcp flags syn ip saddr != 0.0.0.0 update @flood_v4 { ip saddr limit rate over 20/second burst 40 packets } counter drop comment "tcp_syn_flood"
    tcp flags syn ip6 saddr != :: update @flood_v6 { ip6 saddr limit rate over 20/second burst 40 packets } counter drop comment "tcp_syn_flood"


    # UDP FLOOD: max 200 packets/sec per ip
    ip protocol udp ip saddr != 0.0.0.0 update @flood_v4 { ip saddr limit rate over 200/second burst 250 packets } counter drop comment "udp_flood"
    ip6 nexthdr udp ip6 saddr != :: update @flood_v6 { ip6 saddr limit rate over 200/second burst 250 packets } counter drop comment "udp_flood"

    ########################################################

    # honeyport counter for userspace stats
    tcp dport @honey_ports counter queue num 1 comment "honeyport_drop"


    # these port are always transmitted to userspace for DPI, ignores established relation
    tcp dport { 80, 8080 } counter queue num 1


    ip protocol icmp counter queue num 1
    ip6 nexthdr icmpv6 counter queue num 1


    ###  rest connections are considered established
    ct state established,related counter accept




    # other new connections are sent to RuleEngine from userspace
    counter queue num 1


  }


}

EOF

#TODO: trebuie de schimbat 'hook input' in 'hook forward' ca sa fie NETWORK-IPS