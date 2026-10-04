from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.analysis.synthetic_generator import generate_synthetic_scenario

router = APIRouter(prefix="/api/scenarios", tags=["Scenario Generator"])


class SyntheticScenarioRequest(BaseModel):
    scenario_id: str = Field(..., description="Unique scenario ID for the generated scenario")
    name: Optional[str] = Field(None, description="Human-readable scenario name")
    asset_count: int = Field(50, ge=10, le=500, description="Number of assets/nodes (10 - 500)")
    entry_point_ratio: float = Field(0.1, ge=0.01, le=0.5, description="Fraction of nodes that are entry points")
    crown_jewel_ratio: float = Field(0.08, ge=0.01, le=0.5, description="Fraction of nodes that are crown jewels")


@router.post("/generate-synthetic", response_model=Dict[str, Any])
def generate_synthetic(
    request: SyntheticScenarioRequest,
    db: Session = Depends(get_db)
):
    """
    Generate a large-scale realistic multi-tier synthetic topology (50 - 500 nodes)
    with DMZ, App Tier, DB Tier, Management Zone, vulnerabilities, findings, and attack transitions.
    """
    try:
        return generate_synthetic_scenario(
            db=db,
            scenario_id=request.scenario_id,
            name=request.name or f"Synthetic Graph ({request.asset_count} Nodes)",
            asset_count=request.asset_count,
            entry_point_ratio=request.entry_point_ratio,
            crown_jewel_ratio=request.crown_jewel_ratio,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate synthetic scenario: {str(e)}")
