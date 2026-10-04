"""Attack path discovery endpoints."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.analysis.path_analysis import find_attack_paths, get_cheapest_path, get_shortest_path
from backend.app.core.database import get_db
from backend.app.graph.builder import build_canonical_graph
from backend.app.models.database import Scenario

router = APIRouter(prefix="/api/scenarios/{scenario_id}/attack-paths", tags=["Attack Paths"])


@router.get("")
def get_attack_paths(
    scenario_id: str,
    path_mode: Literal["all", "shortest", "cheapest"] = "all",
    max_depth: int = 10,
    max_paths: int = 100,
    db: Session = Depends(get_db),
):
    """
    Get attack paths from entry points to crown jewels for a scenario.
    """
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    graph = build_canonical_graph(db, scenario_id)

    if path_mode == "shortest":
        path = get_shortest_path(graph, max_depth=max_depth)
        paths = [path] if path else []
    elif path_mode == "cheapest":
        path = get_cheapest_path(graph, max_depth=max_depth)
        paths = [path] if path else []
    else:
        paths = find_attack_paths(graph, max_depth=max_depth, max_paths=max_paths)

    return [path.to_dict() for path in paths if path is not None]
