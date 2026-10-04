"""
Pydantic schemas for Edge entity.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class EdgeTypeEnum(StrEnum):
    EXPLOITS = "EXPLOITS"
    CAN_REACH = "CAN_REACH"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    TRUSTED_ACCESS = "TRUSTED_ACCESS"


class EdgeBase(BaseModel):
    source_id: str = Field(..., min_length=1, max_length=100)
    target_id: str = Field(..., min_length=1, max_length=100)
    edge_type: EdgeTypeEnum
    port: int | None = Field(None, ge=1, le=65535)
    protocol: str | None = Field(None, max_length=50)
    traversal_cost: float = Field(..., ge=0.0)
    probability: float = Field(..., ge=0.01, le=1.0)
    finding_id: str | None = Field(None, max_length=100)
    description: str | None = None


class EdgeCreate(EdgeBase):
    id: str = Field(..., min_length=1, max_length=100)


class EdgeUpdate(BaseModel):
    source_id: str | None = Field(None, min_length=1, max_length=100)
    target_id: str | None = Field(None, min_length=1, max_length=100)
    edge_type: EdgeTypeEnum | None = None
    port: int | None = Field(None, ge=1, le=65535)
    protocol: str | None = Field(None, max_length=50)
    traversal_cost: float | None = Field(None, ge=0.0)
    probability: float | None = Field(None, ge=0.01, le=1.0)
    finding_id: str | None = Field(None, max_length=100)
    description: str | None = None


class EdgeResponse(EdgeBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
