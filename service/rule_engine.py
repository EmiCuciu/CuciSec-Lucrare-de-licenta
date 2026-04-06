from typing import List

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

    def evaluate(self, packet_info: PacketInfo):
        """
        Compares the current packet with in-memory rules
        :param packet_info:
        :return: 'ACCEPT' , 'DROP', or 'None'
        """
        if not packet_info:
            return None

        for rule in self._rules:

            ip_match = (
                    rule.ip_src is None or
                    rule.ip_src == "*" or
                    rule.ip_src == packet_info.ip_src
            )
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
                return rule.action

        # if no rules matched
        return None
