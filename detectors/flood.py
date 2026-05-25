import ipaddress
import threading
import time
from collections import defaultdict
from typing import List, Optional

from loguru import logger

from domain.models import PacketInfo
from utils.config import Config


class FloodEngine:
    """
    Userspace sliding-window flood detector.

    Two-layer protection:
      - Kernel layer: nftables rate limits (fast, before NFQUEUE)
      - Userspace layer: per-IP packet counting in TIME_WINDOW seconds

    Whitelisted CIDRs (Config.WHITELIST_CIDRS) are never flood-banned.
    Per-port TCP thresholds (Config.PER_PORT_TCP_THRESHOLDS) override the
    generic MAX_TCP_NEW for sensitive ports (SSH, RDP, DB ports).
    """

    def __init__(self):
        self.ip_history = defaultdict(list)
        self._lock = threading.Lock()

        self.TIME_WINDOW = 12.0    # sliding window in seconds
        self.MAX_TCP_NEW = 200
        self.MAX_UDP_NEW = 250
        self.MAX_ICMP = 30
        self.CLEANUP_INTERVAL = 60.0
        self.MAX_TRACKED_IPS = 50_000

        self.last_cleanup = time.time()

        # pre-compute whitelist networks once at init — O(1) per-packet check
        self._whitelist: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
            ipaddress.ip_network(cidr, strict=False)
            for cidr in Config.WHITELIST_CIDRS
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

        if not ip:
            return None

        if self._is_whitelisted(ip):
            return None

        current_time = time.time()

        # Lazy cleanup of inactive IPs
        if current_time - self.last_cleanup > self.CLEANUP_INTERVAL:
            self._cleanup_old_ips(current_time)
            self.last_cleanup = current_time

        with self._lock:
            if len(self.ip_history) > self.MAX_TRACKED_IPS:
                oldest = sorted(
                    self.ip_history.items(),
                    key=lambda x: max(x[1]) if x[1] else 0
                )[:1000]
                for old_ip, _ in oldest:
                    del self.ip_history[old_ip]
                logger.warning("[FloodEngine] ip_history limit reached — evicted 1000 oldest IPs")

            self.ip_history[ip] = [
                t for t in self.ip_history[ip]
                if current_time - t < self.TIME_WINDOW
            ]
            self.ip_history[ip].append(current_time)
            count = len(self.ip_history[ip])

        proto = packet_info.protocol
        port = packet_info.port_dst

        if proto == "TCP":
            threshold = Config.PER_PORT_TCP_THRESHOLDS.get(port, self.MAX_TCP_NEW)
            if count > threshold:
                logger.critical(
                    f"[FLOOD] {ip} TCP flood on port {port} "
                    f"({count} pkts/{self.TIME_WINDOW}s, threshold={threshold})"
                )
                return f"Persistent TCP Flood on port {port}"

        elif proto == "UDP" and count > self.MAX_UDP_NEW:
            logger.critical(f"[FLOOD] {ip} UDP flood ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent UDP Flood"

        elif proto in ("ICMP", "ICMPv6") and count > self.MAX_ICMP:
            logger.critical(f"[FLOOD] {ip} ICMP flood ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent ICMP Flood"

        return None

    def _cleanup_old_ips(self, current_time: float):
        """
        Deletes old ips which are inactive from 2x TIME_WINDOW
        :param current_time: current time
        :return: None
        """
        with self._lock:
            dead_ips = [
                ip for ip, times in self.ip_history.items()
                if not times or (current_time - max(times)) > self.TIME_WINDOW * 2
            ]

            for ip in dead_ips:
                del self.ip_history[ip]

            if dead_ips:
                logger.debug(f"[FloodEngine] Lazy Cleanup: {len(dead_ips)} inactive IPS erased from RAM.")