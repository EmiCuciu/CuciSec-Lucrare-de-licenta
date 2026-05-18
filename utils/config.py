class Config:
    """
    Config class
    """

    # NFQUEUE
    QUEUE_NUM = 1

    # Honeyports
    HONEY_PORTS = [23, 2323, 3389, 4444, 9999]

    # Flood limits (kernel layer — nftables rate)
    ICMP_RATE = "5/second"
    TCP_SYN_RATE = "20/second"
    UDP_RATE = "200/second"

    # Blacklist
    BLACKLIST_TIMEOUT = "24h"

    # FloodEngine whitelist — these CIDRs are never flood-banned
    # Add the internal subnets from the 3-VM topology to avoid banning the gateway
    WHITELIST_CIDRS = [
        "127.0.0.0/8",       # loopback
        "10.0.2.0/24",       # attacker-facing subnet (VM topology)
        "10.0.3.0/24",       # client-facing subnet (VM topology)
    ]

    # Per-port TCP flood thresholds — override the generic MAX_TCP_NEW = 200
    # Lower thresholds for ports where a burst is clearly an attack
    PER_PORT_TCP_THRESHOLDS = {
        22:   10,   # SSH  — >10 new conns/12s = brute-force
        3306: 20,   # MySQL — >20 = scanning
        5432: 20,   # PostgreSQL
        21:   20,   # FTP
        25:   30,   # SMTP
        3389: 15,   # RDP — moved to honeyports, but threshold kept for safety
    }
