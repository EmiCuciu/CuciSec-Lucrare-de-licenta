import ipaddress
import threading
from typing import List, Tuple, Optional

from loguru import logger

from domain.models import RuleModel, PacketInfo
from repository.rule_repository import RuleRepository
from utils.config import Config

class RuleEngine:
    def __init__(self, rule_repo: RuleRepository = None):
        self._repo = rule_repo or RuleRepository()
        self._rules: List[RuleModel] = []
        self._lock = threading.RLock()
        self.load_rules()

    def load_rules(self):
        """
        Loads rules from db, one time, and stores them into RAM. (Prevents bottleneck)
        :return: NONE
        """
        new_rules = self._repo.get_enabled()
        with self._lock:
            self._rules = new_rules
        logger.info(f"[RuleEngine] {len(self._rules)} rules loaded in RAM")

    def reload_rules(self):
        """
        Hot-Reload rules in RAM from db when adding/deleting a rule
        :return: None
        """
        self.load_rules()

    def evaluate(self, packet_info: PacketInfo) -> Tuple[Optional[str], str]:
        """
        Compares the current packet with in-memory rules.
        Rules are filtered by zone before matching: a rule with zone=WAN only
        applies to WAN packets, zone=LAN only to LAN packets, zone=ANY to both.
        :param packet_info: dissected packet metadata
        :return: Tuple (Action, Zone) or (None, "") if no rule matched
        """
        logger.debug("[RuleEngine] - INSPECTING...")

        if not packet_info:
            return None, ""

        packet_zone = RuleEngine._detect_zone(packet_info.ip_src)

        with self._lock:
            rules = self._rules

        for rule in rules:
            zone = (rule.zone or "WAN").upper()
            if zone != "ANY" and zone != packet_zone:
                continue

            if not RuleEngine.is_ip_match(rule.ip_src, packet_info.ip_src):
                continue

            if not RuleEngine.is_ip_match(rule.ip_dst, packet_info.ip_dst):
                continue

            protocol_match = (
                rule.protocol is None or
                rule.protocol == packet_info.protocol
            )
            if not protocol_match:
                continue

            port_match = True
            if rule.port is not None:
                port_match = (
                    rule.port == packet_info.port_dst or
                    rule.port == packet_info.port_src
                )
            if not port_match:
                continue

            logger.debug(f"[RuleEngine] Rule matched: id={rule.id} zone={zone} action={rule.action}")
            return rule.action, rule.zone or ""

        return None, ""

    @staticmethod
    def _detect_zone(ip_src: str) -> str:
        """
        Determines the zone of a packet based on its source IP.
        Returns 'LAN' if the IP is in any configured LAN_SUBNETS, 'WAN' otherwise.
        """
        try:
            addr = ipaddress.ip_address(ip_src)
            for subnet_str in Config.LAN_SUBNETS:
                if addr in ipaddress.ip_network(subnet_str, strict=False):
                    return "LAN"
        except ValueError:
            pass
        return "WAN"

    @staticmethod
    def is_ip_match(rule_ip: Optional[str], packet_ip: str) -> bool:
        """
        Checks if the rule ip matches the packet ip, supporting exact matches, wildcards, and CIDR notation.
        :param rule_ip: rule ip
        :param packet_ip: packet ip
        :return: boolean
        """
        if not rule_ip or rule_ip == "*":
            return True
        try:
            if '/' in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            return rule_ip == packet_ip
        except ValueError:
            return rule_ip == packet_ip
