class Config:
    """
    Config class
    """

    # NFQUEUE
    QUEUE_NUM = 1

    # Honeyports
    HONEY_PORTS = [
        23,
        2323,
        3389,
        4444,
        9999
    ]

    # Flood detector thresholds
    TIME_WINDOW = 12.0  # sliding window in seconds
    MAX_TCP_NEW = 200
    MAX_UDP_NEW = 250
    MAX_ICMP = 30

    LAN_SUBNETS: list = [
        "10.0.2.0/24",    # Management (NAT VirtualBox)
        "10.0.3.0/24",    # LAN Client
        "172.16.0.0/12",  # RFC1918 Class B
        "192.168.0.0/16", # RFC1918 Class C
        "127.0.0.0/8",    # Loopback IPv4
        "fc00::/7",       # IPv6 ULA
        "fe80::/10",      # IPv6 Link-Local
        "::1/128",        # IPv6 Loopback
    ]
