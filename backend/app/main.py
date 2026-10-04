"""
FastAPI application entrypoint for RiskPath AI - Context-Aware Cybersecurity Decision Support System.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.database import engine
from backend.app.models.database import Base
from backend.data.seeds.seed_data import create_seed_data

from backend.app.routers import (
    health,
    scenarios,
    entities,
    graph,
    paths,
    blast_radius,
    chokepoints,
    prioritization,
    simulation,
    optimization,
    explanation,
    benchmark,
    generator,
    importers,
)

logger = logging.getLogger("riskpath")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager:
    - Auto-creates database schema on server startup
    - Conditionally populates demo seed data if SEED_DEMO_DATA=True
    """
    Base.metadata.create_all(bind=engine)
    if settings.SEED_DEMO_DATA:
        try:
            create_seed_data()
        except Exception:
            logger.exception("Demo seed data initialization notice; continuing without it")
    yield


app = FastAPI(
    title="RiskPath AI - Decision-Support Cybersecurity Engine",
    description=(
        "A graph-based cybersecurity decision-support system for context-aware "
        "vulnerability prioritization, attack path blast radius analysis, "
        "exact budget remediation simulation, and grounded LLM explanations."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS with strict explicit origins and disabled credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler returning clean JSON error responses."""
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred while processing the request."}
    )


# Mount all modular routers
for module in (
    health,
    scenarios,
    entities,
    graph,
    paths,
    blast_radius,
    chokepoints,
    prioritization,
    simulation,
    optimization,
    explanation,
    benchmark,
    generator,
    importers,
):
    app.include_router(module.router)
