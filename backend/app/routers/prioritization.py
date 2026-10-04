"""Context-aware prioritization router."""
from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.database import Scenario
from backend.app.graph.builder import build_canonical_graph
from backend.app.analysis.prioritization import OrderingPolicy, compute_prioritization
from backend.app.schemas.prioritization import PrioritizationResponse

router = APIRouter(prefix="/api/scenarios/{scenario_id}/prioritization", tags=["Prioritization"])


@router.get("", response_model=PrioritizationResponse)
async def get_prioritization(
    scenario_id: str,
    max_depth: int = 10,
    max_paths: int = 100,
    min_operational_score: float = 0.0,
    limit: Optional[int] = None,
    sort_by: Literal[
        "operational_rank",
        "chokepoint_score",
        "cvss",
        "feasibility",
        "asset_criticality",
    ] = "operational_rank",
    crown_jewel_first: bool = True,
    entry_point_first: bool = True,
    kev_tier: bool = True,
    chokepoint_weight: float = 1.0,
    feasibility_weight: float = 1.0,
    cvss_weight: float = 1.0,
    epss_weight: float = 0.5,
    asset_criticality_weight: float = 0.5,
    tiebreaker: Literal["finding_id", "asset_id"] = "finding_id",
    db: Session = Depends(get_db),
) -> PrioritizationResponse:
    """Return contextual prioritization profiles for all active findings."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    if min_operational_score < 0:
        raise HTTPException(
            status_code=400,
            detail="min_operational_score must be >= 0",
        )
    if limit is not None and limit < 0:
        raise HTTPException(status_code=400, detail="limit must be >= 0")

    weight_values = {
        "chokepoint_weight": chokepoint_weight,
        "feasibility_weight": feasibility_weight,
        "cvss_weight": cvss_weight,
        "epss_weight": epss_weight,
        "asset_criticality_weight": asset_criticality_weight,
    }
    for name, value in weight_values.items():
        if value < 0:
            raise HTTPException(
                status_code=400,
                detail=f"{name} must be >= 0",
            )

    try:
        policy = OrderingPolicy(
            crown_jewel_first=crown_jewel_first,
            entry_point_first=entry_point_first,
            kev_tier=kev_tier,
            chokepoint_weight=chokepoint_weight,
            feasibility_weight=feasibility_weight,
            cvss_weight=cvss_weight,
            epss_weight=epss_weight,
            asset_criticality_weight=asset_criticality_weight,
            tiebreaker=tiebreaker,
        )
        graph = build_canonical_graph(db, scenario_id)
        all_results = compute_prioritization(
            graph,
            max_depth=max_depth,
            max_paths=max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    total_findings = len(all_results)
    results = [
        result
        for result in all_results
        if result.operational_score >= min_operational_score
    ]

    if sort_by != "operational_rank":
        sort_keys = {
            "chokepoint_score": lambda r: (-r.profile.finding_chokepoint_score, r.profile.finding_id),
            "cvss": lambda r: (-r.profile.cvss_normalized, r.profile.finding_id),
            "feasibility": lambda r: (
                -r.profile.max_path_feasibility_normalized,
                r.profile.finding_id,
            ),
            "asset_criticality": lambda r: (
                -r.profile.asset_criticality_normalized,
                r.profile.finding_id,
            ),
        }
        results = sorted(results, key=sort_keys[sort_by])

    if limit is not None:
        results = results[:limit]

    return PrioritizationResponse(
        scenario_id=scenario_id,
        total_findings=total_findings,
        returned_findings=len(results),
        max_depth_used=max_depth,
        max_paths_used=max_paths,
        min_operational_score=min_operational_score,
        sort_by=sort_by,
        policy={
            "crown_jewel_first": policy.crown_jewel_first,
            "entry_point_first": policy.entry_point_first,
            "kev_tier": policy.kev_tier,
            "chokepoint_weight": policy.chokepoint_weight,
            "feasibility_weight": policy.feasibility_weight,
            "cvss_weight": policy.cvss_weight,
            "epss_weight": policy.epss_weight,
            "asset_criticality_weight": policy.asset_criticality_weight,
            "tiebreaker": policy.tiebreaker,
        },
        items=[result.to_dict() for result in results],
    )
