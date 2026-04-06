from domain.models import PacketInfo
from repository.base import AsyncDBWriter


class LogRepository:
    """
    DB repository for Log table
    Writings are async with AsyncDBWriter
    """

    def __init__(self):
        self._writer = AsyncDBWriter()

    def insert(self, packet_info: PacketInfo, action_taken: str, details: str = ""):
        """
        Asynchronous inserting
        :param packet_info: PacketInfo object with packet metadata
        :param action_taken: ACCEPT, DROP or BAN
        :param details: optional string with details about the action ( e.g. reason for BAN )
        :return: None
        """
        sql = """
              INSERT INTO Logs (ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details)
              VALUES (?, ?, ?, ?, ?, ?, ?) \
              """

        params = (
            packet_info.ip_src,
            packet_info.ip_dst,
            packet_info.port_src or 0,
            packet_info.port_dst or 0,
            packet_info.protocol,
            action_taken,
            details
        )

        self._writer.execute(sql, params)
