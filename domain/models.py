from dataclasses import dataclass
from typing import Optional


@dataclass
class PacketInfo:
    """
    Pure data object - Dissected object
    """
    ip_src: str
    ip_dst: str
    protocol: str
    port_src: Optional[int] = None
    port_dst: Optional[int] = None
    payload: Optional[str] = None


@dataclass
class RuleModel:
    """
    Static rule from Rules table
    """
    action: str
    enabled: int = 1
    zone: str = "WAN"
    id: Optional[int] = None
    ip_src: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    description: Optional[str] = None


@dataclass
class LogEntry:
    """
    Event logged into Log table
    """
    ip_src: str
    ip_dst: str
    port_src: int
    port_dst: int
    protocol: str
    action_taken: str
    details: str = ""
    id: Optional[int] = None
    timestamp: Optional[str] = None


@dataclass
class BlacklistEntry:
    """
    Blocked ip from Blacklist table
    """
    ip: str
    reason: str
    id: Optional[int] = None
    timestamp: Optional[str] = None
