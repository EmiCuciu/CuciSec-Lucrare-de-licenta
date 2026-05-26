from typing import List

from fastapi import APIRouter, Depends
from loguru import logger

from api.dependencies import get_firewall_actions
from api.schemas import BlacklistResponse, BlacklistCreate
from infrastructure.nftables_manager import NftablesManager
from repository.blacklist_repository import BlacklistRepository
from service.firewall_actions import FirewallActions

router = APIRouter(prefix="/api/blacklist", tags=["Blacklist"])
blacklist_repo = BlacklistRepository()


@router.get("/", response_model=List[BlacklistResponse])
def get_blacklist():
    """
    Retrieves all banned ips from Blacklist table
    :return: List of BlacklistResponse
    """
    logger.debug("[BlacklistRoute] getting all banned ips")
    return blacklist_repo.get_all()


@router.post("/", status_code=201)
def manual_ban(entry: BlacklistCreate,
               firewall_actions: FirewallActions = Depends(get_firewall_actions)):
    """
    Manual ban an ip
    :param entry: source ip to ban
    :param firewall_actions: FirewallActions instance (injected)
    :return: banned ip props
    """
    firewall_actions.ban_ip(entry.ip, entry.reason)
    logger.debug(f"[BlacklistRoute] manual ban for ip {entry.ip} | reason {entry.reason}")
    return {
        "banned": entry.ip,
        "reason": entry.reason
    }

@router.delete("/{ip}")
def unban_ip(ip: str,
             firewall_actions: FirewallActions = Depends(get_firewall_actions)):
    """
    Manual unban an ip
    :param ip: ip to unban
    :param firewall_actions: FirewallActions instance (injected)
    :return: unbanned prop
    """
    blacklist_repo.delete(ip)
    NftablesManager.unban_ip(ip)
    firewall_actions.unban_ip(ip)
    logger.debug(f"[BlacklistRoute] unbanned ip: {ip}")
    return {"unbanned": ip}