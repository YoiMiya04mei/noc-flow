from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AlertRuleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    rule_type: str
    severity: str = "warning"
    threshold_value: float
    is_active: bool = True


class AlertRuleCreate(AlertRuleBase):
    pass


class AlertRuleResponse(AlertRuleBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertIncidentResponse(BaseModel):
    id: int
    rule_id: Optional[int] = None
    severity: str
    title: str
    description: str
    target_entity: str
    status: str
    acknowledged_by: Optional[str] = None
    started_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AlertAcknowledgeRequest(BaseModel):
    notes: Optional[str] = None
