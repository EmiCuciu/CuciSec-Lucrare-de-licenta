import signal
import sys

from loguru import logger
from netfilterqueue import NetfilterQueue

from detectors.dpi import DPIEngine
from detectors.honeyport import HoneyportEngine
from domain.models import PacketInfo
from service.firewall_actions import FirewallActions
from service.packet_analyzer import PacketAnalyzer
from service.rule_engine import RuleEngine
from utils.config import Config


class PacketInterceptor:
    """
    Class responsible with packet takeover from NFQUEUE, using NetFilterQueue, and sending them to UserSpace
    """

    def __init__(self, queue_num: int = Config.QUEUE_NUM):
        self.queue_num = queue_num
        self.nfqueue = NetfilterQueue()
        self.is_running = False

        self.analyzer = PacketAnalyzer()
        self.actions = FirewallActions()
        self.rule_engine = RuleEngine()
        self.dpi = DPIEngine()
        self.honeyport = HoneyportEngine(Config.HONEY_PORTS)

        # Shutdown signal
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum):
        logger.info(f"\n[SIGNAL] {signum} received - shutting down")
        self.stop_interceptor()
        sys.exit(0)

    def _process_packet(self, packet):
        """
        Callback function for every packet from the queue
        turns raw packet into scapy packet and analyze it
        :param packet: packet from NFQUEUE
        :return: None

        FLOW:
            NFTABLE IPS FLOOD (KERNEL)
                -> RULE_ENGINE( STATIC RULE - DROP)
                    -> HONEYPORT
                        -> DPI
                            -> DEFAULT ACCEPT
        """

        raw_payload = packet.get_payload()

        packet_info = self.analyzer.analyze(raw_payload)

        if not packet_info:
            bad = PacketInfo(ip_src="MALFORMED", ip_dst="MALFORMED", protocol="UNKNOWN")
            self.actions.drop_packet(packet, bad, "MALFORMED_PACKET")
            logger.warning("[INTERCEPTOR] Malformed packet or non IP header detected, instant DROP")
            return

        logger.debug(f"[PACKET] {packet_info.protocol} "
                     f"{packet_info.ip_src}:{packet_info.port_src} ->"
                     f"{packet_info.ip_dst}:{packet_info.port_dst}")

        # Rule Engine
        decision = self.rule_engine.evaluate(packet_info)
        if decision == "DROP":
            logger.debug("[INTERCEPTOR] DROP: STATIC RULE")
            self.actions.drop_packet(packet, packet_info, "RULE_ENGINE_DROP")
            return

        # Honeyport
        honey_alert = self.honeyport.inspect(packet_info)
        if honey_alert:
            self.actions.drop_packet(packet, packet_info, f"HONEYPORT_DROP: {honey_alert}")
            self.actions.ban_ip(packet_info.ip_src, reason=honey_alert)
            return

        # DPI
        dpi_alert = self.dpi.inspect(packet_info)
        if dpi_alert:
            self.actions.drop_packet(packet, packet_info, f"DPI_DROP: {dpi_alert}")
            self.actions.ban_ip(packet_info.ip_src, reason=dpi_alert)
            return

        # Rule Engine ACCEPT
        if decision == "ACCEPT":
            logger.debug("[INTERCEPTOR] ACCEPT: STATIC RULE")
            self.actions.accept_packet(packet, packet_info, "RULE_ENGINE_ACCEPT")
            return

        # Default Policy - DEFAULT ACCEPT
        logger.debug("[INTERCEPTOR] ACCEPT: DEFAULT_POLICY")
        self.actions.accept_packet(packet, packet_info, "DEFAULT_ACCEPT")

    def start_interceptor(self):
        """
        Start packet interceptions
        bind NFQUEUE to the callback function that will process each packet
        :return:
        """

        try:

            self.nfqueue.bind(self.queue_num, self._process_packet, max_len=8192)
            self.is_running = True
            logger.info(f"[INTERCEPTOR]. Listening on NFQUEUE {self.queue_num} (max 8192 packets) .. ")

            self.nfqueue.run()  # blocking call, will keep the interceptor running until interrupted


        except Exception as e:
            logger.error(f"\nError in Interceptor: {e}")
            self.stop_interceptor()

    def stop_interceptor(self):
       """
       Stops interception and free resources
       :return:
       """

       if self.is_running:
           logger.info("[INTERCEPTOR] Stop interception and free kernel connection")
           self.nfqueue.unbind()
           self.is_running = False
           self.actions.get_db_writer().stop()
           logger.info("[INTERCEPTOR] Database background worker stopped.")
