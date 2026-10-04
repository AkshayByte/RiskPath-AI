import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from backend.app.analysis.synthetic_generator import (
    ScenarioExistsError,
    generate_synthetic_scenario,
)
from backend.app.core.database import get_db

logger = logging.getLogger("riskpath.generator")
router = APIRouter(prefix="/api/scenarios", tags=["Scenario Generator"])


class SyntheticScenarioRequest(BaseModel):
    scenario_id: str = Field(
        ..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$", description="Unique scenario ID"
    )
    name: str | None = Field(None, max_length=200, description="Human-readable scenario name")
    asset_count: int = Field(50, ge=10, le=500, description="Number of assets/nodes (10 - 500)")
    entry_point_ratio: float = Field(0.1, ge=0.01, le=0.5, description="Fraction of nodes that are entry points")
    crown_jewel_ratio: float = Field(0.08, ge=0.01, le=0.5, description="Fraction of nodes that are crown jewels")
    seed: int = Field(42, ge=0, le=2**31 - 1, description="RNG seed for reproducible graphs")
    overwrite: bool = Field(True, description="Whether to overwrite existing scenario if it exists")

    @model_validator(mode="after")
    def ratios_leave_room_for_intermediate_tiers(self):
        entries = max(1, round(self.asset_count * self.entry_point_ratio))
        jewels = max(1, round(self.asset_count * self.crown_jewel_ratio))
        if entries + jewels > self.asset_count // 2:
            raise ValueError("entry_point_ratio + crown_jewel_ratio leave too few intermediate assets")
        return self


class SyntheticScenarioResponse(BaseModel):
    scenario_id: str
    name: str
    asset_count: int
    finding_count: int
    edge_count: int
    remediation_action_count: int
    entry_points: int
    crown_jewels: int
    seed: int


@router.post("/generate-synthetic", response_model=SyntheticScenarioResponse, status_code=201)
def generate_synthetic(request: SyntheticScenarioRequest, db: Session = Depends(get_db)):
    """
    Generate a large-scale realistic multi-tier synthetic topology (10 - 500 nodes)
    with DMZ, App Tier, DB Tier, Management Zone, vulnerabilities, findings, and attack transitions.
    Fully deterministic and reproducible using isolated `seed`.
    """
    try:
        result = generate_synthetic_scenario(
            db=db,
            scenario_id=request.scenario_id,
            name=request.name or f"Synthetic Graph ({request.asset_count} Nodes)",
            asset_count=request.asset_count,
            entry_point_ratio=request.entry_point_ratio,
            crown_jewel_ratio=request.crown_jewel_ratio,
            seed=request.seed,
            overwrite=request.overwrite,
        )
        db.commit()
        return result
    except ScenarioExistsError as e:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        db.rollback()
        logger.exception("Synthetic scenario generation failed")
        raise HTTPException(status_code=500, detail="Synthetic scenario generation failed due to an internal error.")
