from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class AuditEventResponse(BaseModel):
    id: int
    actor_username: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime

    model_config = {"from_attributes": True}


class AuditEventCreate(BaseModel):
    actor_username: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None
