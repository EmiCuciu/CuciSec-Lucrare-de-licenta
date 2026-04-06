from loguru import logger

from domain.models import PacketInfo


class HoneyportEngine:
    """
    Pro-Active Security drop based on trap ports, any ip that tries to connect to these
    fake port is considered an attack and it is automatically blocked
    """

    def __init__(self, honey_ports):
        self.honey_ports = honey_ports if honey_ports else [23, 2323, 3389, 4444, 9999]

    def inspect(self, packet_info: PacketInfo):
        """
        Verifies if source ip tried to access any fake port
        :param packet_info: packet metadata
        :return: reason for blocking / NONE if pachet is legitim
        """
        logger.debug("[HONEYPORT] - INSPECTING...")
        port_dst = packet_info.port_dst
        protocol = packet_info.protocol

        if protocol in ["TCP", "UDP"] and port_dst in self.honey_ports:
            logger.warning(f"[HONEYPORT ALERT] Suspicious activity -> {protocol}:{port_dst}")
            return f"Honeyport HIT: suspicious activity - dropped ->  {protocol}:{port_dst}"

        return None