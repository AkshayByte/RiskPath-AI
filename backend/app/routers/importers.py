import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.analysis.importers import (
    import_trivy_json, import_nessus_csv, ImportValidationError,
)

logger = logging.getLogger("riskpath.importers")
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB

router = APIRouter(prefix="/api/scenarios", tags=["Scanner Importers"])

ScenarioId = Path(..., min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")


class RawImportRequest(BaseModel):
    content: str = Field(
        ...,
        max_length=MAX_BODY_BYTES,
        description="Raw text content of the scan file (JSON or CSV, up to 10MB)"
    )
    scenario_name: Optional[str] = Field(None, max_length=200, description="Optional name for created scenario")


class ImportResult(BaseModel):
    scenario_id: str
    assets_imported: int
    vulnerabilities_imported: int
    findings_imported: int
    rows_skipped: int = 0
    warnings: List[str] = []
    message: str


def enforce_body_limit(request: Request) -> None:
    """Early content-length check before large buffering."""
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Import payload exceeds 10MB limit.")
        except ValueError:
            pass


def _run_import(db: Session, fn, **kwargs) -> ImportResult:
    try:
        result = fn(db=db, **kwargs)
        db.commit()
        return ImportResult(**result)
    except ImportValidationError as e:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        db.rollback()
        logger.exception("Scanner report import failed")
        raise HTTPException(status_code=500, detail="Scanner report import failed due to an internal server error.")


@router.post(
    "/{scenario_id}/import/trivy",
    response_model=ImportResult,
    dependencies=[Depends(enforce_body_limit)]
)
def import_trivy(
    payload: RawImportRequest,
    scenario_id: str = ScenarioId,
    db: Session = Depends(get_db)
):
    """
    Import Trivy vulnerability scanner JSON output into a scenario.
    """
    return _run_import(
        db=db,
        fn=import_trivy_json,
        scenario_id=scenario_id,
        raw_json_str=payload.content,
        scenario_name=payload.scenario_name
    )


@router.post(
    "/{scenario_id}/import/nessus",
    response_model=ImportResult,
    dependencies=[Depends(enforce_body_limit)]
)
def import_nessus(
    payload: RawImportRequest,
    scenario_id: str = ScenarioId,
    db: Session = Depends(get_db)
):
    """
    Import Nessus or OpenVAS CSV export into a scenario.
    """
    return _run_import(
        db=db,
        fn=import_nessus_csv,
        scenario_id=scenario_id,
        raw_csv_str=payload.content,
        scenario_name=payload.scenario_name
    )
