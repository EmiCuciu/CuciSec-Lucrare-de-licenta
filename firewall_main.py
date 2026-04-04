import os
import sqlite3
import subprocess

from core.interceptor import PacketInterceptor
from database.setup_db import DB_NAME


def setup_kernel_env():
    """
    runs nftables script for initialization
    :return: NONE
    """
    try:
        script_path = os.path.join(os.path.dirname(__file__), "scripts", "nftables_setup.sh")

        subprocess.run(["chmod", "+x", script_path], check=True)

        subprocess.run(["sudo", "bash", script_path], check=True)

    except subprocess.CalledProcessError as e:
        print(f"Error while init nftables:\n {e}")
        exit(1)


def sync_blacklist_to_kernel():
    """
    __FOR BOOTING__
    reloads nft blacklist from DB Blacklist table
    uses (batch processing) for performance
    :return: NONE
    """

    try:
        with sqlite3.connect(DB_NAME) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT ip from Blacklist")

            banned_ips = [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Error reading from db: {e}")

    if not banned_ips:
        print("DB Blacklist empty")
        return

    ipv4_list = [ip for ip in banned_ips if ":" not in ip]
    ipv6_list = [ip for ip in banned_ips if ":" in ip]

    nft_commands = ""

    if ipv4_list:
        ipv4_elements = ", ".join(ipv4_list)
        nft_commands += f"add element inet cucisec blacklist_v4 {{ {ipv4_elements} }}\n"

    if ipv6_list:
        ipv6_elements = ", ".join(ipv6_list)
        nft_commands += f"add element inet cucisec blacklist_v6 {{ {ipv6_elements} }}\n"

    try:
        process = subprocess.Popen(
            ["sudo", "nft", "-f", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        process.communicate(input=nft_commands)

    except Exception as e:
        print(f"[!] Eroare la injectarea regulilor în Kernel: {e}")


def main():
    print("-" * 40)
    print("CuciSec Firewall started")
    print("-" * 40)

    setup_kernel_env()
    print("Kernel initialized (nftables flushed & created)")

    sync_blacklist_to_kernel()
    print("Blacklist synced from DB to Kernel")

    try:
        interceptor = PacketInterceptor(queue_num=1)
        interceptor.start()

    except Exception as e:
        print(f"Error in main: {e}")


if __name__ == "__main__":
    main()
