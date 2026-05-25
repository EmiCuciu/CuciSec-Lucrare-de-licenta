import time
from collections import defaultdict
from typing import Optional
from loguru import logger
from domain.models import PacketInfo
from utils.config import Config
import ipaddress


class FloodEngine:
    """
    Userspace sliding-window flood detector.

    Two-layer protection:
      - Kernel layer: nftables rate limits (fast, before NFQUEUE)
      - Userspace layer: per-IP packet counting in TIME_WINDOW seconds
    """

    def __init__(self):
        self.TIME_WINDOW = 12.0  # sliding window in seconds
        self.MAX_TCP_NEW = 200
        self.MAX_UDP_NEW = 250
        self.MAX_ICMP = 30

        self._history = defaultdict(list)
        self._whitelist = [
            ipaddress.ip_network(c, strict=False)
            for c in Config.WHITELIST_CIDRS
        ]

    def _is_whitelisted(self, ip: str) -> bool:
        """
        Return True if ip belongs to any trusted CIDR in Config.WHITELIST_CIDRS.
        """
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in network for network in self._whitelist)
        except ValueError:
            return False

    def inspect(self, packet_info: PacketInfo) -> Optional[str]:
        """
        Inspect for flood anomaly using a sliding window per source IP.
        :param packet_info: packet metadata
        :return: alert string if flood detected, None otherwise
        """
        ip = packet_info.ip_src
        if not ip or self._is_whitelisted(ip):
            return None

        now = time.time()
        self._history[ip] = [t for t in self._history[ip] if now - t < self.TIME_WINDOW]
        self._history[ip].append(now)
        count = len(self._history[ip])

        proto = packet_info.protocol
        port  = packet_info.port_dst

        if proto == "TCP":
            threshold = Config.PER_PORT_TCP_THRESHOLDS.get(port, self.MAX_TCP_NEW)
            if count > threshold:
                logger.critical(f"[FLOOD] {ip} TCP flood port {port} ({count} pkts/{self.TIME_WINDOW}s)")
                return f"Persistent TCP Flood on port {port}"

        elif proto == "UDP" and count > self.MAX_UDP_NEW:
            logger.critical(f"[FLOOD] {ip} UDP flood ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent UDP Flood"

        elif proto in ("ICMP", "ICMPv6") and count > self.MAX_ICMP:
            logger.critical(f"[FLOOD] {ip} ICMP flood ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent ICMP Flood"

        return None