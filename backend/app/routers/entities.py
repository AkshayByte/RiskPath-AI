"""Entity listing router for assets, findings, edges, and remediation actions."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.database import Asset, Edge, Finding, RemediationAction, Scenario
from backend.app.schemas.asset import AssetResponse
from backend.app.schemas.edge import EdgeResponse
from backend.app.schemas.finding import FindingResponse
from backend.app.schemas.remediation import RemediationActionResponse

router = APIRouter(prefix="/api/scenarios/{scenario_id}", tags=["Entities"])


@router.get("/assets", response_model=list[AssetResponse], tags=["Assets"])
async def get_scenario_assets(scenario_id: str, db: Session = Depends(get_db)):
    """Get all assets in a scenario."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    assets = db.query(Asset).filter(Asset.scenario_id == scenario_id).all()
    return assets


@router.get("/findings", response_model=list[FindingResponse], tags=["Findings"])
async def get_scenario_findings(scenario_id: str, db: Session = Depends(get_db)):
    """Get all findings in a scenario."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    findings = db.query(Finding).filter(Finding.scenario_id == scenario_id).all()
    return findings


@router.get("/edges", response_model=list[EdgeResponse], tags=["Edges"])
async def get_scenario_edges(scenario_id: str, db: Session = Depends(get_db)):
    """Get all edges in a scenario."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    edges = db.query(Edge).filter(Edge.scenario_id == scenario_id).all()
    return edges


@router.get("/remediation-actions", response_model=list[RemediationActionResponse], tags=["Remediation"])
async def get_scenario_remediation_actions(scenario_id: str, db: Session = Depends(get_db)):
    """Get all remediation actions in a scenario."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    actions = db.query(RemediationAction).filter(RemediationAction.scenario_id == scenario_id).all()
    return actions
