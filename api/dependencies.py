from fastapi import Request
from loguru import logger

from infrastructure.nftables_manager import NftablesManager
from service.rule_engine import RuleEngine


def get_rule_engine(request: Request) -> RuleEngine:
    """
    Returns active instance for Rule Engine from app.state at startup
    :usecase: hot-reload
    :param request: request
    :return: RuleEngine instance
    """
    logger.debug("[Dependency] get_rule_engine called")
    return request.app.state.rule_engine

def get_nft_manager() -> NftablesManager:
    """
    Dependency Injection for NftablesManager
    """
    logger.debug("[Dependency] get_nft_manager called")
    return NftablesManager()