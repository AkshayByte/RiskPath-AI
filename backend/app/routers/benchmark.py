"""
Benchmark comparison router (CVSS vs. Context-Aware).
Evaluates empirical risk reduction advantages between isolated CVSS sorting and graph context-aware prioritization.
"""
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.database import Scenario
from backend.app.analysis.benchmark import run_head_to_head_benchmark

logger = logging.getLogger("riskpath.benchmark")
router = APIRouter(prefix="/api/scenarios/{scenario_id}/benchmark", tags=["Benchmark"])

ScenarioId = Path(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$", description="Scenario ID")


class StrategyResult(BaseModel):
    ranked_findings: List[str]
    selected_actions: List[str]
    remaining_paths: int
    paths_eliminated: int
    efficiency: float


class ComparisonSummary(BaseModel):
    additional_paths_cut: int
    advantage_percentage: float
    conclusion: str


class BenchmarkResponse(BaseModel):
    scenario_id: str
    baseline_path_count: int
    baseline_active_findings: int
    cvss_strategy: StrategyResult
    context_aware_strategy: StrategyResult
    comparison: ComparisonSummary


@router.get("", response_model=BenchmarkResponse)
def get_scenario_benchmark(
    scenario_id: str = ScenarioId,
    budget: float = Query(10.0, ge=0.0, le=1000.0, description="Remediation resource budget constraint"),
    db: Session = Depends(get_db),
):
    """
    Run empirical head-to-head comparison: Isolated CVSS-only vs. RiskPath Context-Aware prioritization.
    Measures attack paths eliminated per unit cost under the same budget constraint.
    """
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")

    try:
        result = run_head_to_head_benchmark(db, scenario_id, budget=budget)
        return result.to_dict()
    except Exception as e:
        logger.exception(f"Benchmark calculation failed for scenario '{scenario_id}'")
        raise HTTPException(
            status_code=500,
            detail="Benchmark calculation failed due to an internal server error."
        )
