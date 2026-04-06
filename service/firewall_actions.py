from loguru import logger

from domain.models import PacketInfo, BlacklistEntry
from infrastructure.nftables_manager import NftablesManager
from repository.blacklist_repository import BlacklistRepository
from repository.log_repository import LogRepository


class FirewallActions:
    """
    Class responsible with decisions ( ACCEPT/ DROP/ BAN ), and log actions into Logs table
    """

    def __init__(self):
        self._log_repo = LogRepository()
        self._blacklist_repo = BlacklistRepository()
        self._nft = NftablesManager()

        self._banned_ips: set = set()

    def accept_packet(self, packet, packet_info: PacketInfo, details: str = "DEFAULT_ACCEPT"):
        """
        Allow packet to pass and logs it
        :param packet: NFQUEUE packet object
        :param packet_info: packet metadata
        :param details: string with details about the action
        :return: None
        """
        packet.accept()
        self._log_repo.insert(packet_info, "ACCEPT", details)

    def drop_packet(self, packet, packet_info: PacketInfo, details: str = "BLOCKED"):
        """
        Drop packet and logs it
        :param packet: NFQUEUE packet object
        :param packet_info: dictionary with packet metadata
        :param details: string with details about the action
        :return: None
        """
        packet.drop()
        self._log_repo.insert(packet_info, "DROP", details)

    def ban_ip(self, ip_address: str, reason: str = "Suspicious Activity"):
        """
        Ban source IP in nftables and logs it into Blacklist table
        :param ip_address: IP address to ban
        :param reason: string with reason for banning the IP
        :return:
        """

        if ip_address in self._banned_ips:
            return

        logger.warning(f"[FirewallActions] [BAN] {ip_address} | reason: {reason}")

        self._nft.ban_ip(ip_address)

        entry = BlacklistEntry(ip=ip_address, reason=reason)
        self._blacklist_repo.add(entry)

    @staticmethod
    def get_db_writer():
        """
        Pass async writer for stop in Interceptor
        :return: writer
        """
        from repository.base import AsyncDBWriter
        return AsyncDBWriter()
