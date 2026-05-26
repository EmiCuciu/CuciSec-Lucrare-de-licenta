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

    PER_PORT_TCP_THRESHOLDS = {
        22:   10,
        3306: 20,
        5432: 20,
        21:   20,
        25:   30,
        3389: 15,
    }
