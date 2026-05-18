import json
import os
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
        if not os.path.isfile(script_path):
            raise FileNotFoundError(f"[NftablesManager] nftables script not found: {script_path}")
        try:
            subprocess.run(["chmod", "+x", script_path], check=True)
            subprocess.run(["sudo", "bash", script_path], check=True)
        except subprocess.CalledProcessError as e:
            logger.critical(f"[NftablesManager] Error for setup-script: {e}")
            raise

    @staticmethod
    def ban_ip(ip_address: str):
        """
        Insert ip into kernel blacklist set
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
    def unban_ip(ip_address: str):
        """
        Delete ip from kernel blacklist set
        :param ip_address: ip address to unban
        :return: None
        """
        set_name = "blacklist_v6" if ":" in ip_address else "blacklist_v4"
        cmd = ["sudo", "nft", "delete", "element", "inet", "cucisec",
               set_name, f"{{ {ip_address} }}"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info(f"[NftablesManager] {ip_address} removed from {set_name}")

        except subprocess.CalledProcessError as e:
            logger.warning(f"[NftablesManager] unban_ip: {e.stderr.decode()}")

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

            stdout, stderr = process.communicate(input=commands)
            if process.returncode != 0:
                logger.error(f"[NftablesManager] sync_blacklist failed: {stderr}")
                
        except Exception as e:
            logger.exception(f"[NftablesManager] sync_blacklist error: {e}")

    @staticmethod
    def sync_whitelist(cidrs: List[str]):
        """
        ___FOR BOOT___
        Populate kernel whitelist_v4/v6 sets from Config.WHITELIST_CIDRS.
        Must be called after setup() so the sets already exist.
        :param cidrs: list of CIDR strings (e.g. ["10.0.2.0/24", "127.0.0.0/8"])
        :return: None
        """
        ipv4 = [c for c in cidrs if ":" not in c]
        ipv6 = [c for c in cidrs if ":" in c]

        commands = ""
        if ipv4:
            commands += f"add element inet cucisec whitelist_v4 {{ {', '.join(ipv4)} }}\n"
        if ipv6:
            commands += f"add element inet cucisec whitelist_v6 {{ {', '.join(ipv6)} }}\n"

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
            stdout, stderr = process.communicate(input=commands)
            if process.returncode != 0:
                logger.error(f"[NftablesManager] sync_whitelist failed: {stderr}")
            else:
                logger.info(f"[NftablesManager] Whitelist synced: {len(cidrs)} CIDRs → kernel")
        except Exception as e:
            logger.exception(f"[NftablesManager] sync_whitelist error: {e}")

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