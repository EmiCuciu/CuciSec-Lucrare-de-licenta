from fastapi import Request
from loguru import logger

from service.firewall_actions import FirewallActions
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


def get_firewall_actions(request: Request) -> FirewallActions:
    """
    Returns active FirewallActions instance from app.state
    :usecase: cache invalidation on unban
    :param request: request
    :return: FirewallActions instance
    """
    logger.debug("[Dependency] get_firewall_actions called")
    return request.app.state.firewall_actions