import ipaddress
from typing import List, Tuple, Optional

from loguru import logger

from domain.models import RuleModel, PacketInfo
from repository.rule_repository import RuleRepository


class RuleEngine:
    def __init__(self, rule_repo: RuleRepository = None):
        self._repo = rule_repo or RuleRepository()
        self._rules: List[RuleModel] = []
        self.load_rules()

    def load_rules(self):
        """
        Loads rules from db, one time, and stores them into RAM. (Prevents bottleneck)
        :return: NONE
        """
        self._rules = self._repo.get_enabled()
        logger.info(f"[RuleEngine] {len(self._rules)} rules loaded in RAM")

    def reload_rules(self):
        """
        Hot-Reload rules in RAM from db when adding/deleting a rule
        :return: None
        """
        self.load_rules()
        logger.info("[RuleEngine] rules reloaded into RAM")

    def evaluate(self, packet_info: PacketInfo) -> Tuple[Optional[str], str]:
        """
        Compares the current packet with in-memory rules
        :param packet_info:
        :return: Tuple (Action, Zone)
        """
        if not packet_info:
            return None, ""

        for rule in self._rules:

            ip_match = RuleEngine.is_ip_match(rule.ip_src, packet_info.ip_src)

            protocol_match = (
                    rule.protocol is None or
                    rule.protocol == packet_info.protocol
            )

            port_match = True
            if rule.port is not None:
                port_match = (
                        rule.port == packet_info.port_dst or
                        rule.port == packet_info.port_src
                )

            if ip_match and protocol_match and port_match:
                return rule.action, rule.zone or ""

        # if no rules matched
        return None, ""

    @staticmethod
    def is_ip_match(rule_ip: str, packet_ip: str) -> bool:
        """
        Checks if the rule ip matches the packet ip, supporting exact matches, wildcards, and CIDR notation.
        :param rule_ip: rule ip
        :param packet_ip: packet ip
        :return: boolean
        """
        if not rule_ip or rule_ip == "*":
            return True
        try:
            # check if the rule IP is a network block (CIDR notation: 192.168.1.0/24)
            if '/' in rule_ip:
                network = ipaddress.ip_network(rule_ip, strict=False)
                ip_to_check = ipaddress.ip_address(packet_ip)
                return ip_to_check in network

            # match fallback
            return rule_ip == packet_ip
        except ValueError:
            # failsafe if string is malformed
            return rule_ip == packet_ip
