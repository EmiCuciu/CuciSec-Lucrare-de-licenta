import os.path

from loguru import logger

from database.setup_db import init_db
from infrastructure.interceptor import PacketInterceptor
from infrastructure.nftables_manager import NftablesManager
from repository.blacklist_repository import BlacklistRepository
from utils.config import Config
from utils.logger import setup_logger

interceptor: PacketInterceptor = None


def main():
    setup_logger()

    logger.info("-" * 40)
    logger.info("[BOOT]CuciSec Firewall started")
    logger.info("-" * 40)

    init_db()

    nft = NftablesManager
    script_path = os.path.join(os.path.dirname(__file__), "scripts", "nftables_setup.sh")
    nft.setup(script_path)
    logger.info("[BOOT] Kernel initialized (nftables flushed & created)")

    blacklist_repo = BlacklistRepository()
    blk_ips = blacklist_repo.get_all_ips()
    ipv4_list = [ip for ip in blk_ips if ":" not in ip]
    ipv6_list = [ip for ip in blk_ips if ":" in ip]
    nft.sync_blacklist(ipv4_list, ipv6_list)
    logger.info(f"[BOOT] Blacklist synced: {len(blk_ips)} IPS from DB to Kernel")

    global interceptor

    try:
        interceptor = PacketInterceptor(Config.QUEUE_NUM)
        interceptor.start_interceptor()

    except Exception as e:
        logger.error(f"Error in main: {e}")


if __name__ == "__main__":
    main()
