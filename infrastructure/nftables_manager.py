import json
import os
import subprocess
import threading
import time
from typing import List

from loguru import logger

from repository.stats_repository import StatsRepository
from service.stats_service import StatsService


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

    @staticmethod
    def start_counter_snapshot_thread(interval: int = 5):
        """
        Background thread: every `interval` seconds reads nftables counters,
        computes the delta from the last snapshot, and persists it to DB.
        """
        previous = {
            "tcp_syn_flood_dropped": 0,
            "icmp_flood_dropped": 0,
            "udp_flood_dropped": 0,
            "blacklist_dropped": 0,
            "honeyport_hits": 0
        }

        def _run():
            nonlocal previous
            while True:
                time.sleep(interval)
                try:
                    nft_json = NftablesManager.get_stats()
                    current = StatsService.parse_flood_counters(nft_json)
                    delta = StatsService.compute_delta(current, previous)

                    if any(delta.values()):
                        StatsRepository.accumulate_kernel_counters(delta)

                    previous = current
                except Exception as e:
                    logger.error(f"[CounterSnapshot] error: {e}")

        t = threading.Thread(target=_run, daemon=True, name="counter-snapshot")
        t.start()