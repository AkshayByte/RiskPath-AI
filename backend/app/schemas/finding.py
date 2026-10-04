"""
Pydantic schemas for Finding entity.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class FindingStatusEnum(StrEnum):
    ACTIVE = "active"
    REMEDIATED = "remediated"
    SUPPRESSED = "suppressed"
    IN_PROGRESS = "in_progress"


class FindingBase(BaseModel):
    asset_id: str = Field(..., min_length=1, max_length=100)
    vulnerability_id: str = Field(..., min_length=1, max_length=100)
    port: int | None = Field(None, ge=1, le=65535)
    service_name: str | None = Field(None, max_length=255)
    status: FindingStatusEnum = FindingStatusEnum.ACTIVE
    discovered_at: datetime | None = None


class FindingCreate(FindingBase):
    id: str = Field(..., min_length=1, max_length=100)


class FindingUpdate(BaseModel):
    asset_id: str | None = Field(None, min_length=1, max_length=100)
    vulnerability_id: str | None = Field(None, min_length=1, max_length=100)
    port: int | None = Field(None, ge=1, le=65535)
    service_name: str | None = Field(None, max_length=255)
    status: FindingStatusEnum | None = None
    discovered_at: datetime | None = None


class FindingResponse(FindingBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
