from loguru import logger
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.packet import Raw

from domain.models import PacketInfo


class PacketAnalyzer:
    """
    Class responsible for packet dissection, raw_packets with raw_bytes
    Transform byte string into a structured dictionary with IP, Port, Protocol, Payload
    """

    @staticmethod
    def analyze(raw_payload: bytes) -> PacketInfo | None:
        """
        Packet dissection function, transform raw_packet into a structured dictionary with network metadata
        :param raw_payload: byte string from NFQUEUE
        :return: packet_info : PacketInfo entity [ ip_src, ip_dst, protocol, port_src, port_dst, payload ]
        :return: None : if packet doesn't have IP layer or is malformed
        """

        try:
            if not raw_payload:
                return None

            # Verify ip version reading first 4 bits
            version = raw_payload[0] >> 4

            if version == 4:
                packet = IP(raw_payload)
                ip_layer = IP

            elif version == 6:
                packet = IPv6(raw_payload)
                ip_layer = IPv6

            else:
                return None

        except Exception as e:
            logger.error(f"[PacketAnalyzer] Error: {e}")
            return None


        # Extract basic metadata ( Layer 3 )
        packet_info = PacketInfo(
            ip_src=packet[ip_layer].src,
            ip_dst=packet[ip_layer].dst,
            protocol="UNKNOWN"
        )

        # Identify protocol and ports ( Layer 4 )
        if packet.haslayer(TCP):
            packet_info.protocol = "TCP"
            packet_info.port_src = packet[TCP].sport
            packet_info.port_dst = packet[TCP].dport

        elif packet.haslayer(UDP):
            packet_info.protocol = "UDP"
            packet_info.port_src = packet[UDP].sport
            packet_info.port_dst = packet[UDP].dport

        elif packet.haslayer(ICMP):
            # ICMP doesn't have ports, but we can use type and code to identify the message type
            # type 8 = "echo request"
            # type 0 = "echo reply"
            packet_info.protocol = "ICMP"
            packet_info.port_dst = packet[ICMP].type

        elif ip_layer == IPv6 and packet[IPv6].nh == 58:
            # Protocol 58 in IPv6 means ICMPv6
            packet_info.protocol = "ICMPv6"

            if packet.haslayer(ICMPv6EchoRequest):
                packet_info.port_dst = 128

            elif packet.haslayer(ICMPv6EchoReply):
                packet_info.port_dst = 129


        # Extract the payload for DPI  ( Layer 7 )
        if packet.haslayer(Raw):
            try:
                # try to make readable text ( for SQLI and XSS attacks )
                packet_info.payload = packet[Raw].load.decode('utf-8', errors='ignore')
            except Exception as e:
                # if it is binary format, keep it as string representation of bytes (file transfer, malware, etc.)
                packet_info.payload = str(packet[Raw].load)
                logger.exception(f"{e}")

        return packet_info
