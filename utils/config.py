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
    WHITELIST_CIDRS = [
        "127.0.0.0/8",
        "10.0.2.0/24",
        "10.0.3.0/24",
    ]

    MANAGEMENT_ALLOWED_CIDRS = ["127.0.0.1", "10.0.3.0/24", "10.0.2.0/24"]

    PER_PORT_TCP_THRESHOLDS = {
        22:   10,
        3306: 20,
        5432: 20,
        21:   20,
        25:   30,
        3389: 15,
    }
