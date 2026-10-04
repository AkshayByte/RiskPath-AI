"""Blast radius reachability analysis endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.database import Scenario
from backend.app.graph.builder import build_canonical_graph
from backend.app.analysis.blast_radius import compute_blast_radius
from backend.app.schemas.blast_radius import BlastRadiusResponse

router = APIRouter(prefix="/api/scenarios/{scenario_id}/blast-radius", tags=["Blast Radius"])


@router.get("/{source_asset_id}", response_model=BlastRadiusResponse)
def get_blast_radius(
    scenario_id: str,
    source_asset_id: str,
    max_depth: int = 10,
    db: Session = Depends(get_db),
):
    """
    Compute the blast radius from a compromised asset in a scenario.
    """
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    graph = build_canonical_graph(db, scenario_id)

    try:
        result = compute_blast_radius(
            graph,
            source_asset_id,
            max_depth=max_depth,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result.to_dict()
