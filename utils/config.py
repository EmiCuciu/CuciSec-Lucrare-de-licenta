class Config:
    """
    Config class
    """

    # NFQUEUE
    QUEUE_NUM = 1

    # Honeyports
    HONEY_PORTS = [23, 2323, 3389, 4444, 9999]

    # Flood limits
    ICMP_RATE = "5/second"
    TCP_SYN_RATE = "20/second"
    UDP_RATE = "200/second"

    # Blacklist
    BLACKLIST_TIMEOUT = "24h"
