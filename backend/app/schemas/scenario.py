"""
Pydantic schemas for Scenario entity.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScenarioBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1000)


class ScenarioCreate(ScenarioBase):
    id: str = Field(..., min_length=1, max_length=100)


class ScenarioUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1000)


class ScenarioResponse(ScenarioBase):
    id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
