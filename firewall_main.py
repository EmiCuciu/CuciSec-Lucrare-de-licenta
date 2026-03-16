import sqlite3
import subprocess

from core.interceptor import PacketInterceptor
from database.setup_db import DB_NAME


def sync_blacklist_to_kernel():
    """
    __FOR BOOTING__
    reloads nft blacklist from DB Blacklist table
    :return: NONE
    """

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    try:

        cursor.execute("""
                       SELECT ip
                       from Blacklist
                       """)

        banned_ips = cursor.fetchall()

        if not banned_ips:
            print("DB Blacklist empty")
            return

        for ip_tuple in banned_ips:
            ip = ip_tuple[0]
            try:
                cmd = f"sudo nft add element inet cucisec blacklist {{ {ip} }}"
                subprocess.run(cmd, shell=True, check=True, stderr=subprocess.DEVNULL)  # DEVNULL to suppress errors
                print(f"IP: {ip} added into nftables blacklist")

            except subprocess.CalledProcessError:
                print(f"IP: {ip} already exists in nftables blacklist, skipping...")

        print(f"Blacklist synchronization complete. Total IPs loaded: {len(banned_ips)}")

    except Exception as e:
        print(f"Error reading from DB Blacklist table: {e}")
    finally:
        if connection:
            connection.close()


def main():
    print("-" * 40)
    print("CuciSec Firewall started")
    print("-" * 40)

    sync_blacklist_to_kernel()

    try:
        interceptor = PacketInterceptor(queue_num=1)
        interceptor.start()

    except Exception as e:
        print(f"Error in main: {e}")


if __name__ == "__main__":
    main()