"""
Pydantic schemas for Asset entity.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AssetTypeEnum(StrEnum):
    WORKSTATION = "workstation"
    WEB_SERVER = "web_server"
    APP_SERVER = "app_server"
    DATABASE = "database"
    IDENTITY_PROVIDER = "identity_provider"
    CLOUD_STORAGE = "cloud_storage"
    API_GATEWAY = "api_gateway"
    DOMAIN_CONTROLLER = "domain_controller"


class EnvironmentEnum(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    DMZ = "dmz"
    INTERNAL = "internal"


class NetworkZoneEnum(StrEnum):
    EXTERNAL = "external"
    DMZ = "dmz"
    APP_TIER = "app_tier"
    DB_TIER = "db_tier"
    MANAGEMENT = "management"


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: AssetTypeEnum
    criticality: float = Field(..., ge=1.0, le=10.0)
    environment: EnvironmentEnum
    network_zone: NetworkZoneEnum
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    owner: str = Field(..., min_length=1, max_length=255)
    ip_address: str | None = None
    description: str | None = None


class AssetCreate(AssetBase):
    id: str = Field(..., min_length=1, max_length=100)


class AssetUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    type: AssetTypeEnum | None = None
    criticality: float | None = Field(None, ge=1.0, le=10.0)
    environment: EnvironmentEnum | None = None
    network_zone: NetworkZoneEnum | None = None
    is_entry_point: bool | None = None
    is_crown_jewel: bool | None = None
    owner: str | None = Field(None, min_length=1, max_length=255)
    ip_address: str | None = None
    description: str | None = None


class AssetResponse(AssetBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
