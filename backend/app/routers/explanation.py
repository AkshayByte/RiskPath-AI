"""AI and deterministic explanation router."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.analysis import explanation as explanation_mod
from backend.app.analysis.budget_optimization import MAX_CANDIDATE_ACTIONS, optimize, resolve_candidates
from backend.app.analysis.prioritization import OrderingPolicy, compute_prioritization
from backend.app.analysis.remediation_simulation import resolve_simulation_action, run_simulation
from backend.app.core.database import get_db
from backend.app.graph.builder import build_canonical_graph
from backend.app.models.database import RemediationAction, Scenario
from backend.app.schemas.explanation import (
    FindingExplanationRequest,
    OptimizationExplanationRequest,
    SimulationExplanationRequest,
)
from backend.app.services import explanation_provider as provider_mod

router = APIRouter(prefix="/api/scenarios/{scenario_id}/explain", tags=["Explanation"])


@router.post("")
async def explain(
    scenario_id: str,
    request: dict,
    db: Session = Depends(get_db),
) -> dict:
    """Explain deterministic analysis results (read-only; never mutates state)."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not isinstance(request, dict):
        raise HTTPException(status_code=400, detail="Request body must be an object")
    explanation_type = request.get("explanation_type")
    if explanation_type == "finding":
        try:
            typed = FindingExplanationRequest(**request)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deterministic, assembled = _explain_finding_evidence(db, scenario_id, typed)
    elif explanation_type == "simulation":
        try:
            typed = SimulationExplanationRequest(**request)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deterministic, assembled = _explain_simulation_evidence(db, scenario_id, typed)
    elif explanation_type == "optimization":
        try:
            typed = OptimizationExplanationRequest(**request)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deterministic, assembled = _explain_optimization_evidence(db, scenario_id, typed)
    else:
        raise HTTPException(
            status_code=400,
            detail=("Unsupported explanation_type; must be one of finding, simulation, optimization"),
        )

    try:
        provider = provider_mod.get_default_provider()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    explanation, status_val, origin = explanation_mod.explain_with_provider(
        assembled, provider, request.get("user_question")
    )
    return {
        "deterministic_result": deterministic,
        "explanation": {
            "scenario_id": scenario_id,
            "explanation_type": explanation_type,
            **explanation,
            "status": status_val,
            "origin": origin,
        },
    }


def _explain_finding_evidence(db: Session, scenario_id: str, typed: FindingExplanationRequest):
    """Reconstruct finding evidence from current prioritization output."""
    if typed.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if typed.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    try:
        policy = OrderingPolicy(
            crown_jewel_first=typed.crown_jewel_first,
            entry_point_first=typed.entry_point_first,
            kev_tier=typed.kev_tier,
            chokepoint_weight=typed.chokepoint_weight,
            feasibility_weight=typed.feasibility_weight,
            cvss_weight=typed.cvss_weight,
            epss_weight=typed.epss_weight,
            asset_criticality_weight=typed.asset_criticality_weight,
            tiebreaker=typed.tiebreaker,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    graph = build_canonical_graph(db, scenario_id)
    try:
        results = compute_prioritization(
            graph,
            max_depth=typed.max_depth,
            max_paths=typed.max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    match = next((r for r in results if r.profile.finding_id == typed.finding_id), None)
    if match is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Finding '{typed.finding_id}' is not represented in the current "
                "active-finding prioritization view and cannot be explained "
                "through it"
            ),
        )
    deterministic = match.to_dict()
    assembled = explanation_mod.assemble_finding_evidence(deterministic)
    return deterministic, assembled


def _explain_simulation_evidence(db: Session, scenario_id: str, typed: SimulationExplanationRequest):
    """Reconstruct simulation evidence by running the simulation engine."""
    if not typed.remediation_action_ids:
        raise HTTPException(status_code=400, detail="At least one remediation action is required")
    if typed.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if typed.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    try:
        policy = OrderingPolicy(
            crown_jewel_first=typed.crown_jewel_first,
            entry_point_first=typed.entry_point_first,
            kev_tier=typed.kev_tier,
            chokepoint_weight=typed.chokepoint_weight,
            feasibility_weight=typed.feasibility_weight,
            cvss_weight=typed.cvss_weight,
            epss_weight=typed.epss_weight,
            asset_criticality_weight=typed.asset_criticality_weight,
            tiebreaker=typed.tiebreaker,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rows = db.query(RemediationAction).filter(RemediationAction.id.in_(typed.remediation_action_ids)).all()
    found_ids = {str(row.id) for row in rows}
    for requested_id in typed.remediation_action_ids:
        if requested_id not in found_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation action '{requested_id}' not found",
            )
    try:
        actions = [
            resolve_simulation_action(row, scenario_id)
            for row in sorted(
                rows,
                key=lambda r: typed.remediation_action_ids.index(str(r.id)),
            )
        ]
        ordered: list = []
        by_id = {a.action_id: a for a in actions}
        for requested_id in typed.remediation_action_ids:
            ordered.append(by_id[requested_id])
        graph = build_canonical_graph(db, scenario_id)
        result = run_simulation(
            graph,
            ordered,
            max_depth=typed.max_depth,
            max_paths=typed.max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    deterministic = result.to_dict()
    deterministic["simulated_at"] = str(deterministic.get("simulated_at"))
    assembled = explanation_mod.assemble_simulation_evidence(deterministic)
    return deterministic, assembled


def _explain_optimization_evidence(db: Session, scenario_id: str, typed: OptimizationExplanationRequest):
    """Reconstruct optimization evidence by running the optimizer."""
    if not typed.candidate_action_ids:
        raise HTTPException(status_code=400, detail="At least one candidate action is required")
    if len(typed.candidate_action_ids) > MAX_CANDIDATE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"At most {MAX_CANDIDATE_ACTIONS} candidate actions are supported "
                f"for exact enumeration, got {len(typed.candidate_action_ids)}"
            ),
        )
    if len(set(typed.candidate_action_ids)) != len(typed.candidate_action_ids):
        raise HTTPException(status_code=400, detail="Duplicate candidate_action_ids are not allowed")
    if typed.budget < 0:
        raise HTTPException(status_code=400, detail="budget must be >= 0")
    if typed.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if typed.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    rows = db.query(RemediationAction).filter(RemediationAction.id.in_(typed.candidate_action_ids)).all()
    found_ids = {str(row.id) for row in rows}
    for requested_id in typed.candidate_action_ids:
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
            budget=typed.budget,
            max_depth=typed.max_depth,
            max_paths=typed.max_paths,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    deterministic = result.to_dict()
    deterministic["optimized_at"] = str(deterministic.get("optimized_at"))
    assembled = explanation_mod.assemble_optimization_evidence(deterministic)
    return deterministic, assembled
