import os.path
import threading

import uvicorn
from loguru import logger

from api.api_main import create_app
from database.setup_db import init_db
from infrastructure.interceptor import PacketInterceptor
from infrastructure.nftables_manager import NftablesManager
from repository.blacklist_repository import BlacklistRepository
from utils.config import Config
from utils.logger import setup_logger


def start_api(rule_engine, firewall_actions):
    """
    Runs FastApi on another thread
    :param rule_engine: RuleEngine
    :param firewall_actions: FirewallActions
    :return: None
    """
    app = create_app(
        rule_engine=rule_engine,
        firewall_actions=firewall_actions,
    )
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

def main():
    setup_logger()

    logger.info("-" * 40)
    logger.info("[BOOT] CuciSec Firewall started")
    logger.info("-" * 40)

    init_db()
    logger.info("[BOOT] Database initialized")


    script_path = os.path.join(os.path.dirname(__file__), "scripts", "nftables_setup.sh")
    NftablesManager.setup(script_path)
    logger.info("[BOOT] Kernel initialized (nftables flushed & created)")

    blacklist_repo = BlacklistRepository()
    blk_ips = blacklist_repo.get_all_ips()
    ipv4_list = [ip for ip in blk_ips if ":" not in ip]
    ipv6_list = [ip for ip in blk_ips if ":" in ip]
    NftablesManager.sync_blacklist(ipv4_list, ipv6_list)
    logger.info(f"[BOOT] Blacklist synced: {len(blk_ips)} IPS from DB to Kernel")

    interceptor = PacketInterceptor(Config.QUEUE_NUM)

    NftablesManager.start_counter_snapshot_thread(interval=60)

    api_thread = threading.Thread(
        target=start_api,
        args=(interceptor.rule_engine, interceptor.actions),
        daemon=True
    )
    api_thread.start()
    logger.info("[BOOT] FastAPI running on http://0.0.0.0:8000")
    logger.info("[BOOT] API docs: http://0.0.0.0:8000/docs")

    try:
        interceptor.start_interceptor()

    except Exception as e:
        logger.error(f"Error in main: {e}")


if __name__ == "__main__":
    main()
