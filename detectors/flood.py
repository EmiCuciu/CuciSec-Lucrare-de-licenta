import threading
import time
from collections import defaultdict

from loguru import logger

from domain.models import PacketInfo


class FloodEngine:
    """
    Count how many times an IP tries to initiate new connections in a small interval
    """

    def __init__(self):

        # dict with ip as key and list of timestamps as value, for counting new connections in TIME_WINDOW
        self.ip_history = defaultdict(list)

        self._lock = threading.Lock()
        self.TIME_WINDOW = 12.0     # 12 seconds admitted flood for graphic visualize

        self.MAX_TCP_NEW = 200
        self.MAX_UDP_NEW = 250
        self.MAX_ICMP = 30

        self.last_cleanup = time.time()
        self.CLEANUP_INTERVAL = 60.0

    def inspect(self, packet_info: PacketInfo):
        """
        Inspect for anomaly flood
        :param packet_info:
        :return:
        """

        ip = packet_info.ip_src

        if not ip or ip == "127.0.0.1":
            return None

        current_time = time.time()

        # Lazy cleanup
        if current_time - self.last_cleanup > self.CLEANUP_INTERVAL:
            self._cleanup_old_ips(current_time)
            self.last_cleanup = current_time

        with self._lock:
            self.ip_history[ip] = [
                t for t in self.ip_history[ip]
                if current_time - t < self.TIME_WINDOW
            ]
            self.ip_history[ip].append(current_time)
            count = len(self.ip_history[ip])

        proto = packet_info.protocol

        if proto == "TCP" and count > self.MAX_TCP_NEW:
            logger.critical(f"[FLOOD] {ip} is flooding TCP ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent TCP SYN Flood"

        elif proto == "UDP" and count > self.MAX_UDP_NEW:
            logger.critical(f"[FLOOD] {ip} is flooding UDP ({count} pkts/{self.TIME_WINDOW}s)")
            return "Persistent UDP Flood"

        elif proto in ["ICMP", "ICMPv6"] and count > self.MAX_ICMP:
            logger.critical(f"[FLOOD] {ip} is flooding ICMP ({count} pkts/{self.TIME_WINDOW}s)")
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