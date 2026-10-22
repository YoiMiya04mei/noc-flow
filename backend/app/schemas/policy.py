import ipaddress
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class PrefixAllowlistBase(BaseModel):
    prefix: str = Field(..., description="CIDR prefix to allowlist (e.g. 203.0.113.0/24)")
    description: Optional[str] = None
    is_active: bool = True

    @field_validator("prefix")
    @classmethod
    def validate_prefix_guardrail(cls, v: str) -> str:
        clean_prefix = v.strip()
        try:
            net = ipaddress.ip_network(clean_prefix, strict=False)
        except ValueError:
            raise ValueError(f"Invalid network CIDR representation: {clean_prefix}")

        # Safety Guardrail: Permanent rejection of default routes
        if (net.version == 4 and net.prefixlen == 0) or (net.version == 6 and net.prefixlen == 0):
            raise ValueError("SAFETY GUARDRAIL VIOLATION: Default route (0.0.0.0/0 or ::/0) can NEVER be allowlisted!")

        # Safety Guardrail: Reject link-local, loopback, and multicast ranges
        if net.is_loopback:
            raise ValueError("SAFETY GUARDRAIL VIOLATION: Loopback address ranges cannot be allowlisted!")
        if net.is_multicast:
            raise ValueError("SAFETY GUARDRAIL VIOLATION: Multicast ranges cannot be allowlisted!")
        if net.is_link_local:
            raise ValueError("SAFETY GUARDRAIL VIOLATION: Link-local ranges cannot be allowlisted!")

        # Enforce reasonable prefix lengths for ISP routing
        if net.version == 4:
            if net.prefixlen < 8 or net.prefixlen > 24:
                raise ValueError("IPv4 prefix length must be between /8 and /24 for BGP route intelligence!")
        elif net.version == 6:
            if net.prefixlen < 20 or net.prefixlen > 48:
                raise ValueError("IPv6 prefix length must be between /20 and /48 for BGP route intelligence!")

        return str(net)


class PrefixAllowlistCreate(PrefixAllowlistBase):
    pass


class PrefixAllowlistResponse(PrefixAllowlistBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class PeerAllowlistBase(BaseModel):
    peer_ip: str
    peer_asn: int = Field(..., gt=0)
    description: Optional[str] = None
    is_active: bool = True

    @field_validator("peer_ip")
    @classmethod
    def validate_peer_ip(cls, v: str) -> str:
        clean_ip = v.strip()
        try:
            ip = ipaddress.ip_address(clean_ip)
        except ValueError:
            raise ValueError(f"Invalid peer IP address: {clean_ip}")
        if ip.is_loopback or ip.is_multicast:
            raise ValueError("Peer IP cannot be loopback or multicast!")
        return str(ip)


class PeerAllowlistCreate(PeerAllowlistBase):
    pass


class PeerAllowlistResponse(PeerAllowlistBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ScoringPolicyBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    latency_weight: float = Field(default=0.35, ge=0.0, le=1.0)
    loss_weight: float = Field(default=0.30, ge=0.0, le=1.0)
    jitter_weight: float = Field(default=0.15, ge=0.0, le=1.0)
    cost_weight: float = Field(default=0.10, ge=0.0, le=1.0)
    utilization_weight: float = Field(default=0.10, ge=0.0, le=1.0)
    hold_down_minutes: int = Field(default=15, ge=1)
    hysteresis_threshold_pct: float = Field(default=15.0, ge=1.0, le=100.0)
    is_active: bool = True


class ScoringPolicyCreate(ScoringPolicyBase):
    pass


class ScoringPolicyResponse(ScoringPolicyBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}
