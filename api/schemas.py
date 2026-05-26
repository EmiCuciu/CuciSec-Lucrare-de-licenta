import ipaddress
from typing import Optional, List

from pydantic import BaseModel, field_validator, ConfigDict


# Very cool ~~~ pydantic ~~~

class RuleCreate(BaseModel):
    """
    Schema for ( POST /rules )
    """
    ip_src: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    action: str
    description: Optional[str] = None
    enabled: int = 1
    zone: str = "WAN"

    @field_validator("action")
    @classmethod
    def valid_action(cls, v: str):
        if v.upper() not in ("ACCEPT", "DROP"):
            raise ValueError("action must be ACCEPT or DROP")
        return v.upper()

    @field_validator("protocol")
    @classmethod
    def protocol_valid(cls, v: str):
        if v is not None and v.upper() not in ("TCP", "UDP", "ICMP", "ICMPV6"):
            raise ValueError("protocol must be TCP, UDP, ICMP, ICMPv6")
        return v.upper() if v else None

    @field_validator("port")
    @classmethod
    def port_valid(cls, v: int):
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("wrong port, must be between 1 and 65535")
        return v



class RuleResponse(BaseModel):
    """
    Schema for ( GET / rules )
    """
    id: int
    ip_src: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    action: str
    description: Optional[str]
    enabled: int
    zone: str

    # ~~~ cool ~~~
    model_config = ConfigDict(from_attributes=True)

class LogResponse(BaseModel):
    """
    Schema for ( GET / logs )
    """
    id: int
    timestamp: str
    ip_src: str
    ip_dst: str
    port_src: int
    port_dst: int
    protocol: str
    action_taken: str
    details: str

    model_config = ConfigDict(from_attributes=True)


class BlacklistCreate(BaseModel):
    """
    Schema for ( POST / blacklist )
    """
    ip: str
    reason: str = "Manual Ban"

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{v}'")
        return v

class BlacklistResponse(BaseModel):
    """
    Schema for ( GET / blacklist )
    """
    id: int
    ip: str
    reason: str
    timestamp: str

    model_config = ConfigDict(from_attributes=True)

class StatsResponse(BaseModel):
    """
    Schema for ( GET / stats )
    """
    total_logs: int
    accepted: int
    dropped: int
    banned_ips: int
    total_intercepted: int   # userspace logs + kernel drops (all sessions + real-time)
    flood_counters: dict     # previous sessions (DB baseline) + current session (live nftables)
    dpi_drops: int = 0
    recent_bans: List[dict] = []

    model_config = ConfigDict(from_attributes=True)