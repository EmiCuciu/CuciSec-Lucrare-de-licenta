import queue
import sqlite3
import subprocess
import threading

from database.setup_db import DB_NAME


class FirewallActions:
    """
    Class responsible with decisions ( ACCEPT/ DROP/ BAN ), and log actions into Logs table
    """

    def __init__(self, db_path=DB_NAME):
        self.db_path = db_path

        self.log_queue = queue.Queue()

        self.db_worker = threading.Thread(target=self.async_db_writer, daemon=True)
        self.db_worker.start()

    def _log_to_db(self, packet_data, action_taken, details=""):
        """
        Function that store packet into Logs
        :param packet_data: dictionary with packet metadata ( ip_src, ip_dst, protocol, port_src, port_dst, payload )
        :param action_taken: ACCEPT, DROP or BAN
        :param details: optional string with details about the action ( e.g. reason for BAN )
        :return: None
        """
        self.log_queue.put((packet_data, action_taken, details))

    def async_db_writer(self):
        """
        Producer-Consumer pattern, asynchronous logging into Logs table
        :return: None
        """
        connection_worker = sqlite3.connect(self.db_path, check_same_thread=False)
        cursor = connection_worker.cursor()

        while True:
            log_item = self.log_queue.get()

            if log_item is None:
                break

            if len(log_item) == 4 and log_item[3] == "blacklist":
                packet_data, _, reason, _ = log_item
                try:
                    cursor.execute(
                        "INSERT OR IGNORE INTO Blacklist (ip, reason) VALUES (?, ?)",
                        (packet_data["ip_src"], reason)
                    )
                    connection_worker.commit()

                except Exception as e:
                    print(f"Worker Blacklist Error: {e}")
                finally:
                    self.log_queue.task_done()
                continue



            packet_data, action_taken, details = log_item

            try:
                ip_src = packet_data.get("ip_src", "UNKNOWN")
                ip_dst = packet_data.get("ip_dst", "UNKNOWN")
                port_src = packet_data.get("port_src") or 0
                port_dst = packet_data.get("port_dst") or 0
                protocol = packet_data.get("protocol", "UNKNOWN")

                cursor.execute("""
                               INSERT INTO Logs (ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details)
                               VALUES (?, ?, ?, ?, ?, ?, ?)
                               """, (ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details))
                connection_worker.commit()
            except Exception as e:
                print(f" Worker Error : {e}")
            finally:
                self.log_queue.task_done()

    def stop_worker(self):
        """
        Stops the logging thread
        :return: None
        """
        self.log_queue.put(None)
        self.db_worker.join()

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

        ban_log_data = {
            "ip_src": ip_address,
            "ip_dst": "N/A",
            "protocol": "N/A",
            "port_src": 0,
            "port_dst": 0
        }

        self.log_queue.put((ban_log_data, "BAN", reason, "blacklist"))

        # Add IP to Blacklist table (Kernel / nftables )
        try:
            set_name = "blacklist_v6" if ":" in ip_address else "blacklist_v4"

            cmd = ["sudo", "nft", "add", "element", "inet", "cucisec", set_name, f"{{ {ip_address} }}"]
            subprocess.run(cmd, check=True)
            print(f"IP: {ip_address} added into {set_name}")

        except subprocess.CalledProcessError as e:
            print(f"Error inserting into Blacklist table (Kernel / nftables): {e}")
