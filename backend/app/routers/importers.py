from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.analysis.importers import import_trivy_json, import_nessus_csv

router = APIRouter(prefix="/api/scenarios", tags=["Scanner Importers"])


class RawImportRequest(BaseModel):
    content: str = Field(
        ...,
        max_length=10_000_000,
        description="Raw text content of the scan file (JSON or CSV, up to 10MB)"
    )
    scenario_name: Optional[str] = Field(None, max_length=200, description="Optional name for created scenario")


@router.post("/{scenario_id}/import/trivy", response_model=Dict[str, Any])
def import_trivy(
    scenario_id: str,
    payload: RawImportRequest,
    db: Session = Depends(get_db)
):
    """
    Import Trivy vulnerability scanner JSON output into a scenario.
    """
    try:
        return import_trivy_json(
            db=db,
            scenario_id=scenario_id,
            raw_json_str=payload.content,
            scenario_name=payload.scenario_name
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse Trivy report: {str(e)}")


@router.post("/{scenario_id}/import/nessus", response_model=Dict[str, Any])
def import_nessus(
    scenario_id: str,
    payload: RawImportRequest,
    db: Session = Depends(get_db)
):
    """
    Import Nessus or OpenVAS CSV export into a scenario.
    """
    try:
        return import_nessus_csv(
            db=db,
            scenario_id=scenario_id,
            raw_csv_str=payload.content,
            scenario_name=payload.scenario_name
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse Nessus CSV report: {str(e)}")
