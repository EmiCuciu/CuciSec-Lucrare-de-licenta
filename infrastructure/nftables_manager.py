import json
import subprocess
from typing import List

from loguru import logger


class NftablesManager:
    """
    Infrastructure class: nft commands are managed here
    """

    @staticmethod
    def setup(script_path: str):
        """
        runs nftables script for initialization
        :param script_path: path
        :return: None
        """
        try:
            subprocess.run(["chmod", "+x", script_path], check=True)
            subprocess.run(["sudo", "bash", script_path], check=True)
        except subprocess.CalledProcessError as e:
            logger.critical(f"[NftablesManager] Error for setup-script: {e}")
            raise

    @staticmethod
    def ban_ip(ip_address: str):
        """
        Insert ip into kernel blacklist
        :param ip_address: ip address to ban
        :return: None
        """

        set_name = "blacklist_v6" if ":" in ip_address else "blacklist_v4"

        cmd = ["sudo", "nft", "add", "element", "inet", "cucisec", set_name, f"{{ {ip_address} }}"]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"[NftablesManager] IP: {ip_address} added into {set_name}")

        except subprocess.CalledProcessError as e:
            logger.error(f"[NftablesManager] Error inserting into Blacklist table (Kernel / nftables): {e.stderr.decode()}")

    @staticmethod
    def sync_blacklist(ipv4_list: List[str], ipv6_list: List[str]):
        """
        ___FOR BOOT___
        Batch inserting with lists
        :param ipv4_list: list of ipv4 addresses to ban
        :param ipv6_list: list of ipv6 addresses to ban
        :return: None
        """
        commands = ""
        if ipv4_list:
            commands += f"add element inet cucisec blacklist_v4 {{ {', '.join(ipv4_list)} }}\n"
        if ipv6_list:
            commands += f"add element inet cucisec blacklist_v6 {{ {', '.join(ipv6_list)} }}\n"

        if not commands:
            return

        try:
            process = subprocess.Popen(
                ["sudo", "nft", "-f", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            process.communicate(input=commands)
        except Exception as e:
            logger.exception(f"[NftablesManager] sync_blacklist error: {e}")

    @staticmethod
    def get_stats() -> dict:
        """
        Read contor from Kernel and format to JSON
        :return: dictionary with all the ruleset in JSON format
        """
        try:
            result = subprocess.run(
                ["sudo", "nft", "-j", "list", "ruleset"],
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)

        except Exception as e:
            logger.exception(f"[NftablesManager] get_stats() error: {e}")
            return {}

    @staticmethod
    def cleanup():
        """
        Deletes the cucisec table from Kernel on shutdown
        This prevents the system from dropping packets when the userspace app dies
        """
        try:
            subprocess.run(["sudo", "nft", "delete", "table", "inet", "cucisec"], check=False, capture_output=True)
            logger.info("[NftablesManager] Table 'cucisec' deleted. Network restored to normal.")
        except Exception as e:
            logger.error(f"[NftablesManager] Cleanup error: {e}")