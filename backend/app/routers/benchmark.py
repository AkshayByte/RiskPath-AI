"""Benchmark comparison router (CVSS vs. Context-Aware)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.database import Scenario
from backend.app.analysis.benchmark import run_head_to_head_benchmark

router = APIRouter(prefix="/api/scenarios/{scenario_id}/benchmark", tags=["Benchmark"])


@router.get("")
async def get_scenario_benchmark(
    scenario_id: str,
    budget: float = 10.0,
    db: Session = Depends(get_db),
):
    """
    Run empirical head-to-head comparison: Isolated CVSS-only vs. RiskPath Context-Aware prioritization.
    """
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    if budget < 0:
        raise HTTPException(status_code=400, detail="budget must be >= 0")

    result = run_head_to_head_benchmark(db, scenario_id, budget=budget)
    return result.to_dict()
