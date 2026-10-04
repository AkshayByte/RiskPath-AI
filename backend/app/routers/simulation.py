"""Remediation what-if simulation router."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.analysis.prioritization import OrderingPolicy
from backend.app.analysis.remediation_simulation import (
    resolve_simulation_action,
    run_simulation,
)
from backend.app.core.database import get_db
from backend.app.graph.builder import build_canonical_graph
from backend.app.models.database import RemediationAction, Scenario
from backend.app.schemas.remediation_simulation import (
    SimulationRequest,
    SimulationResponse,
)

router = APIRouter(prefix="/api/scenarios/{scenario_id}", tags=["Simulation"])


@router.post(
    "/simulate-remediation",
    response_model=SimulationResponse,
)
def simulate_remediation(
    scenario_id: str,
    request: SimulationRequest,
    db: Session = Depends(get_db),
) -> SimulationResponse:
    """Run deterministic what-if remediation simulation (no persistent mutation)."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not request.remediation_action_ids:
        raise HTTPException(status_code=400, detail="At least one remediation action is required")
    if request.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if request.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")

    try:
        policy = OrderingPolicy(
            crown_jewel_first=request.crown_jewel_first,
            entry_point_first=request.entry_point_first,
            kev_tier=request.kev_tier,
            chokepoint_weight=request.chokepoint_weight,
            feasibility_weight=request.feasibility_weight,
            cvss_weight=request.cvss_weight,
            epss_weight=request.epss_weight,
            asset_criticality_weight=request.asset_criticality_weight,
            tiebreaker=request.tiebreaker,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    rows = db.query(RemediationAction).filter(RemediationAction.id.in_(request.remediation_action_ids)).all()
    found_ids = {str(row.id) for row in rows}
    for requested_id in request.remediation_action_ids:
        if requested_id not in found_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation action '{requested_id}' not found",
            )

    try:
        actions = [
            resolve_simulation_action(row, scenario_id)
            for row in sorted(rows, key=lambda r: request.remediation_action_ids.index(str(r.id)))
        ]
        ordered: list = []
        by_id = {a.action_id: a for a in actions}
        for requested_id in request.remediation_action_ids:
            ordered.append(by_id[requested_id])
        graph = build_canonical_graph(db, scenario_id)
        result = run_simulation(
            graph,
            ordered,
            max_depth=request.max_depth,
            max_paths=request.max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return SimulationResponse(**result.to_dict())
