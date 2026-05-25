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
                         + global aggregate counting (defeats --rand-source)
    """

    def __init__(self):
        self.TIME_WINDOW = 12.0  # sliding window in seconds
        self.MAX_TCP_NEW = 200
        self.MAX_UDP_NEW = 250
        self.MAX_ICMP = 30

        # global aggregate thresholds (all IPs combined) — DDOS
        self.GLOBAL_MAX_SYN  = 400
        self.GLOBAL_MAX_UDP  = 500
        self.GLOBAL_MAX_ICMP = 60

        self._history = defaultdict(list)
        self._global_history: dict[str, list] = {"TCP": [], "UDP": [], "ICMP": [], "ICMPv6": []}
        self._whitelist = [
            ipaddress.ip_network(c, strict=False)
            for c in Config.WHITELIST_CIDRS
        ]

    def _is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in network for network in self._whitelist)
        except ValueError:
            return False

    def _check_global_rate(self, proto: str, now: float) -> Optional[str]:
        bucket = self._global_history.get(proto, [])
        bucket = [t for t in bucket if now - t < self.TIME_WINDOW]
        bucket.append(now)
        self._global_history[proto] = bucket
        count = len(bucket)

        if proto == "TCP" and count > self.GLOBAL_MAX_SYN:
            logger.critical(f"[FLOOD] GLOBAL TCP SYN flood ({count} pkts/{self.TIME_WINDOW}s) — likely rand-source")
            return f"Global TCP SYN Flood ({count} pkts)"
        if proto == "UDP" and count > self.GLOBAL_MAX_UDP:
            logger.critical(f"[FLOOD] GLOBAL UDP flood ({count} pkts/{self.TIME_WINDOW}s) — likely rand-source")
            return f"Global UDP Flood ({count} pkts)"
        if proto in ("ICMP", "ICMPv6") and count > self.GLOBAL_MAX_ICMP:
            logger.critical(f"[FLOOD] GLOBAL ICMP flood ({count} pkts/{self.TIME_WINDOW}s) — likely rand-source")
            return f"Global ICMP Flood ({count} pkts)"
        return None

    def inspect(self, packet_info: PacketInfo) -> Optional[tuple[str, bool]]:
        """
        Inspect for flood anomaly , prevents Dos-DDos attacks
        :param packet_info: packet metadata
        :return: (alert_string, should_ban) tuple if flood detected, None otherwise.
                 should_ban=False for global/rand-source floods (IPs are fake).
        """
        logger.debug("[FLOOD] - INSPECTING...")

        ip = packet_info.ip_src
        proto = packet_info.protocol
        port = packet_info.port_dst
        now = time.time()

        global_alert = self._check_global_rate(proto, now)
        if global_alert:
            return global_alert, False

        if not ip or self._is_whitelisted(ip):
            return None

        self._history[ip] = [t for t in self._history[ip] if now - t < self.TIME_WINDOW]
        self._history[ip].append(now)
        count = len(self._history[ip])

        if proto == "TCP":
            threshold = Config.PER_PORT_TCP_THRESHOLDS.get(port, self.MAX_TCP_NEW)
            if count > threshold:
                logger.critical(f"[FLOOD] {ip} TCP flood port {port} ({count} pkts/{self.TIME_WINDOW}s)")
                return f"Persistent TCP Flood on port {port}", True

        elif proto == "UDP" and count > self.MAX_UDP_NEW:
            logger.critical(f"[FLOOD] {ip} UDP flood ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent UDP Flood", True

        elif proto in ("ICMP", "ICMPv6") and count > self.MAX_ICMP:
            logger.critical(f"[FLOOD] {ip} ICMP flood ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent ICMP Flood", True

        return None