from typing import List

from fastapi import APIRouter
from loguru import logger

from api.schemas import BlacklistResponse, BlacklistCreate
from domain.models import BlacklistEntry
from infrastructure.nftables_manager import NftablesManager
from repository.blacklist_repository import BlacklistRepository

router = APIRouter(prefix="/api/blacklist", tags=["Blacklist"])
blacklist_repo = BlacklistRepository


@router.get("/", response_model=List[BlacklistResponse])
def get_blacklist():
    """
    Retrieves all banned ips from Blacklist table
    :return: List of BlacklistResponse
    """
    logger.debug("[BlacklistRoute] getting all banned ips")
    return blacklist_repo.get_all()


@router.post("/", status_code=201)
def manual_ban(entry: BlacklistCreate):
    """
    Manual ban an ip
    :param entry: source ip to ban
    :return: banned ip props
    """
    blacklist_entry = BlacklistEntry(ip=entry.ip, reason=entry.reason)
    blacklist_repo.add(blacklist_entry)
    NftablesManager.ban_ip(entry.ip)
    logger.debug(f"[BlacklistRoute] manual ban for ip {entry.ip} | reason {entry.reason}")
    return {
        "banned": entry.ip,
        "reason": entry.reason
    }

@router.delete("/{ip}")
def unban_ip(ip: str):
    """
    Manual unban an ip
    :param ip: ip to unban
    :return: unbanned prop
    """
    blacklist_repo.delete(ip)
    logger.debug(f"[BlacklistRoute] unbanning ip: {ip}")
    return { "unbanned": ip }