import time
from typing import Optional

from loguru import logger

from domain.models import PacketInfo
from utils.config import Config


class FloodEngine:
    """
    Userspace per-source flood detector.
    Global and per-destination flood are handled entirely by nftables (kernel).
    This layer detects sustained per-source floods and returns an alert → DROP + BAN.
    """

    def __init__(self):
        self._history: dict[tuple[str, str], list[float]] = {}

    def inspect(self, packet_info: PacketInfo) -> Optional[str]:
        """
        Returns alert string if per-source flood detected (caller does DROP + BAN).
        Returns None if packet is within limits.
        """
        logger.debug("[FLOOD] - INSPECTING...")

        ip = packet_info.ip_src
        proto = packet_info.protocol
        port = packet_info.port_dst
        now = time.time()
        key = (ip, proto)

        window = [t for t in self._history.get(key, []) if now - t < Config.TIME_WINDOW]
        window.append(now)
        self._history[key] = window
        count = len(window)

        if proto == "TCP":
            threshold = Config.PER_PORT_TCP_THRESHOLDS.get(port, Config.MAX_TCP_NEW)
            if count > threshold:
                logger.critical(f"[FLOOD] {ip} TCP flood port {port} ({count} pkts/{Config.TIME_WINDOW}s)")
                return f"Persistent TCP Flood on port {port}"

        elif proto == "UDP" and count > Config.MAX_UDP_NEW:
            logger.critical(f"[FLOOD] {ip} UDP flood ({count} pkts/{Config.TIME_WINDOW}s)")
            return "Persistent UDP Flood"

        elif proto in ("ICMP", "ICMPv6") and count > Config.MAX_ICMP:
            logger.critical(f"[FLOOD] {ip} ICMP flood ({count} pkts/{Config.TIME_WINDOW}s)")
            return "Persistent ICMP Flood"

        return None