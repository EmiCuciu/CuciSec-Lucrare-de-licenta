import sqlite3
import subprocess

from database.setup_db import DB_NAME


class FirewallActions:
    """
    Class responsible with decisions ( ACCEPT/ DROP/ BAN ), and log actions into Logs table
    """

    def __init__(self, db_path=DB_NAME):
        self.db_path = db_path

    def _log_to_db(self, packet_data, action_taken, details=""):
        """
        Function that store packet into Logs
        :param packet_data: dictionary with packet metadata ( ip_src, ip_dst, protocol, port_src, port_dst, payload )
        :param action_taken: ACCEPT, DROP or BAN
        :param details: optional string with details about the action ( e.g. reason for BAN )
        :return: None
        """
        try:
            connection = sqlite3.connect(self.db_path)
            cursor = connection.cursor()

            # with default values for db consistency
            ip_src = packet_data.get("ip_src", "UNKNOWN")
            ip_dst = packet_data.get("ip_dst", "UNKNOWN")
            port_src = packet_data.get("port_src") or 0
            port_dst = packet_data.get("port_dst") or 0
            protocol = packet_data.get("protocol", "UNKNOWN")

            cursor.execute("""
                           INSERT INTO Logs (ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details)
                           VALUES (?, ?, ?, ?, ?, ?, ?)
                           """, (ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details))

            connection.commit()
            connection.close()

        except Exception as e:
            print(f"Error inserting into Logs table: {e}")

    def accept_packet(self, packet, packet_data, details="ACCEPTED"):
        """
        Allow packet to pass and logs it
        :param packet: NFQUEUE packet object
        :param packet_data: dictionary with packet metadata
        :param details: string with details about the action
        :return: None
        """
        packet.accept()
        self._log_to_db(packet_data, "ACCEPT", details)

    def drop_packet(self, packet, packet_data, details="BLOCKED"):
        """
        Drop packet and logs it
        :param packet: NFQUEUE packet object
        :param packet_data: dictionary with packet metadata
        :param details: string with details about the action
        :return: None
        """
        packet.drop()
        self._log_to_db(packet_data, "DROP", details)

    def ban_ip(self, ip_address, reason="Suspicious Activity"):
        """
        Ban source IP in nftables and logs it into Blacklist table
        :param ip_address: IP address to ban
        :param reason: string with reason for banning the IP
        :return:
        """

        print(f"IPS Alert: Banning IP {ip_address} for reason: {reason}")

        # Add IP to Blacklist table (CuciSec.db)
        try:
            connection = sqlite3.connect(DB_NAME)
            cursor = connection.cursor()

            cursor.execute("""
                           INSERT INTO Blacklist (ip, reason)
                           VALUES (?, ?)
                           """, (ip_address, reason))

            connection.commit()
            connection.close()

        except Exception as e:
            print(f"Error inserting into Blacklist table (CuciSec.db): {e}")

        # Add IP to Blacklist table (Kernel / nftables )
        try:
            cmd = f"sudo nft add element inet cucisec blacklist {{ {ip_address} }}"
            subprocess.run(cmd, shell=True, check=True)
            print(f"IP: {ip_address} added into nftables blacklist")
        except subprocess.CalledProcessError as e:
            print(f"Error inserting into Blacklist table (Kernel / nftables): {e}")
