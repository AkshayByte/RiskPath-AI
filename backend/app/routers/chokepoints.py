"""Chokepoint bottleneck analysis endpoints."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.analysis.chokepoint import compute_chokepoints
from backend.app.core.database import get_db
from backend.app.graph.builder import build_canonical_graph
from backend.app.models.database import Scenario
from backend.app.schemas.chokepoint import ChokepointResponse

router = APIRouter(prefix="/api/scenarios/{scenario_id}/chokepoints", tags=["Chokepoint"])


@router.get("", response_model=ChokepointResponse)
def get_chokepoints(
    scenario_id: str,
    max_depth: int = 10,
    max_paths: int = 100,
    entity_type: Literal["all", "asset", "finding"] = "all",
    min_score: float = 0.0,
    limit: int | None = None,
    db: Session = Depends(get_db),
):
    """
    Compute chokepoints from attack paths in a scenario.
    """
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    if limit is not None and limit < 0:
        raise HTTPException(status_code=400, detail="limit must be >= 0")
    if not (0.0 <= min_score <= 1.0):
        raise HTTPException(status_code=400, detail="min_score must be between 0.0 and 1.0")

    graph = build_canonical_graph(db, scenario_id)

    try:
        result = compute_chokepoints(
            graph,
            max_depth=max_depth,
            max_paths=max_paths,
            entity_types=entity_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    chokepoints = result.chokepoints

    if min_score > 0.0:
        chokepoints = [c for c in chokepoints if c.chokepoint_score >= min_score]

    if limit is not None:
        chokepoints = chokepoints[:limit]

    return ChokepointResponse(
        chokepoints=chokepoints,
        total_entities_analyzed=result.total_entities_analyzed,
        max_chokepoint_score=result.max_chokepoint_score,
        total_attack_paths_analyzed=result.total_attack_paths_analyzed,
        max_depth_used=result.max_depth_used,
        max_paths_used=result.max_paths_used,
    )
