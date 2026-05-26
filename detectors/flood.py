import time
from collections import defaultdict
from typing import Optional

from loguru import logger

from domain.models import PacketInfo
from utils.config import Config


class FloodEngine:
    """
    Userspace sliding-window flood detector.

    Two-layer protection:
      - Kernel layer: nftables rate limits (fast, before NFQUEUE)
      - Userspace layer: per-IP packet counting in TIME_WINDOW seconds
                         + global aggregate counting (defeats --rand-source)
    """

    def __init__(self):
        self._history = defaultdict(list)
        self._global_history: dict[str, list] = {"TCP": [], "UDP": [], "ICMP": [], "ICMPv6": []}

    def _check_global_rate(self, proto: str, now: float) -> Optional[str]:
        bucket = self._global_history.get(proto, [])
        bucket = [t for t in bucket if now - t < Config.TIME_WINDOW]
        bucket.append(now)
        self._global_history[proto] = bucket
        count = len(bucket)

        if proto == "TCP" and count > Config.GLOBAL_MAX_SYN:
            logger.critical(f"[FLOOD] GLOBAL TCP SYN flood ({count} pkts/{Config.TIME_WINDOW}s) — likely rand-source")
            return f"Global TCP SYN Flood ({count} pkts)"
        if proto == "UDP" and count > Config.GLOBAL_MAX_UDP:
            logger.critical(f"[FLOOD] GLOBAL UDP flood ({count} pkts/{Config.TIME_WINDOW}s) — likely rand-source")
            return f"Global UDP Flood ({count} pkts)"
        if proto in ("ICMP", "ICMPv6") and count > Config.GLOBAL_MAX_ICMP:
            logger.critical(f"[FLOOD] GLOBAL ICMP flood ({count} pkts/{Config.TIME_WINDOW}s) — likely rand-source")
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

        self._history[ip] = [t for t in self._history[ip] if now - t < Config.TIME_WINDOW]
        self._history[ip].append(now)
        count = len(self._history[ip])

        if proto == "TCP":
            threshold = Config.PER_PORT_TCP_THRESHOLDS.get(port, Config.MAX_TCP_NEW)
            if count > threshold:
                logger.critical(f"[FLOOD] {ip} TCP flood port {port} ({count} pkts/{Config.TIME_WINDOW}s)")
                return f"Persistent TCP Flood on port {port}", True

        elif proto == "UDP" and count > Config.MAX_UDP_NEW:
            logger.critical(f"[FLOOD] {ip} UDP flood ({count} pkts/{Config.TIME_WINDOW}s)")
            return "Persistent UDP Flood", True

        elif proto in ("ICMP", "ICMPv6") and count > Config.MAX_ICMP:
            logger.critical(f"[FLOOD] {ip} ICMP flood ({count} pkts/{Config.TIME_WINDOW}s)")
            return "Persistent ICMP Flood", True

        return None
