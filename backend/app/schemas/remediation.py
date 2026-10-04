"""
Pydantic schemas for RemediationAction entity.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RemediationActionTypeEnum(StrEnum):
    PATCH_VULNERABILITY = "PATCH_VULNERABILITY"
    REMOVE_VULNERABILITY = "REMOVE_VULNERABILITY"
    DISABLE_SERVICE = "DISABLE_SERVICE"
    REMOVE_NETWORK_PATH = "REMOVE_NETWORK_PATH"
    SEGMENT_NETWORK = "SEGMENT_NETWORK"
    RESTRICT_PORT = "RESTRICT_PORT"
    REMOVE_TRUST_RELATIONSHIP = "REMOVE_TRUST_RELATIONSHIP"
    REDUCE_PRIVILEGE = "REDUCE_PRIVILEGE"
    CHANGE_ACCESS_POLICY = "CHANGE_ACCESS_POLICY"
    ISOLATE_ASSET = "ISOLATE_ASSET"


class RemediationActionBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1)
    action_type: RemediationActionTypeEnum
    target_asset_id: str | None = Field(None, max_length=100)
    target_finding_id: str | None = Field(None, max_length=100)
    target_edge_id: str | None = Field(None, max_length=100)
    estimated_cost: float = Field(..., ge=0.0)
    implementation_complexity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH)$")
    downtime_required: bool = False


class RemediationActionCreate(RemediationActionBase):
    id: str = Field(..., min_length=1, max_length=100)


class RemediationActionUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, min_length=1)
    action_type: RemediationActionTypeEnum | None = None
    target_asset_id: str | None = Field(None, max_length=100)
    target_finding_id: str | None = Field(None, max_length=100)
    target_edge_id: str | None = Field(None, max_length=100)
    estimated_cost: float | None = Field(None, ge=0.0)
    implementation_complexity: str | None = Field(None, pattern="^(LOW|MEDIUM|HIGH)$")
    downtime_required: bool | None = None


class RemediationActionResponse(RemediationActionBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
