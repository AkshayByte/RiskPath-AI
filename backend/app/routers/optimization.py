"""Budget-constrained remediation optimization router."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.database import RemediationAction, Scenario
from backend.app.graph.builder import build_canonical_graph
from backend.app.analysis.budget_optimization import (
    MAX_CANDIDATE_ACTIONS,
    optimize,
    resolve_candidates,
)
from backend.app.schemas.budget_optimization import (
    OptimizationRequest,
    OptimizationResponse,
)

router = APIRouter(prefix="/api/scenarios/{scenario_id}", tags=["Optimization"])


@router.post(
    "/optimize-remediation",
    response_model=OptimizationResponse,
)
def optimize_remediation(
    scenario_id: str,
    request: OptimizationRequest,
    db: Session = Depends(get_db),
) -> OptimizationResponse:
    """Select the optimal feasible remediation set under a budget (read-only)."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not request.candidate_action_ids:
        raise HTTPException(
            status_code=400, detail="At least one candidate action is required"
        )
    if len(request.candidate_action_ids) > MAX_CANDIDATE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"At most {MAX_CANDIDATE_ACTIONS} candidate actions are supported "
                f"for exact enumeration, got {len(request.candidate_action_ids)}"
            ),
        )
    if len(set(request.candidate_action_ids)) != len(request.candidate_action_ids):
        raise HTTPException(
            status_code=400, detail="Duplicate candidate_action_ids are not allowed"
        )
    if request.budget < 0:
        raise HTTPException(status_code=400, detail="budget must be >= 0")
    if request.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if request.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")

    rows = (
        db.query(RemediationAction)
        .filter(RemediationAction.id.in_(request.candidate_action_ids))
        .all()
    )
    found_ids = {str(row.id) for row in rows}
    for requested_id in request.candidate_action_ids:
        if requested_id not in found_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation action '{requested_id}' not found",
            )

    try:
        candidates = resolve_candidates(rows, scenario_id)
        graph = build_canonical_graph(db, scenario_id)
        result = optimize(
            graph,
            candidates,
            budget=request.budget,
            max_depth=request.max_depth,
            max_paths=request.max_paths,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return OptimizationResponse(**result.to_dict())
