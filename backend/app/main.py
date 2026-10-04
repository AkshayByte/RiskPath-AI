"""
FastAPI application entrypoint for RiskPath AI - Context-Aware Cybersecurity Decision Support System.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.database import engine
from backend.app.models.database import Base
from backend.data.seeds.seed_data import create_seed_data

from backend.app.routers.health import router as health_router
from backend.app.routers.scenarios import router as scenarios_router
from backend.app.routers.entities import router as entities_router
from backend.app.routers.graph import router as graph_router
from backend.app.routers.paths import router as paths_router
from backend.app.routers.blast_radius import router as blast_radius_router
from backend.app.routers.chokepoints import router as chokepoints_router
from backend.app.routers.prioritization import router as prioritization_router
from backend.app.routers.simulation import router as simulation_router
from backend.app.routers.optimization import router as optimization_router
from backend.app.routers.explanation import router as explanation_router
from backend.app.routers.benchmark import router as benchmark_router
from backend.app.routers.generator import router as generator_router
from backend.app.routers.importers import router as importers_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan context manager:
    - Auto-creates database schema on startup
    - Idempotently ensures seed data is present (Docker & local dev parity)
    """
    Base.metadata.create_all(bind=engine)
    try:
        create_seed_data()
    except Exception as e:
        print(f"[RiskPath AI] Startup seed notice: {e}")
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

# Configure CORS for local development and containerized setups
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all modular routers
app.include_router(health_router)
app.include_router(scenarios_router)
app.include_router(entities_router)
app.include_router(graph_router)
app.include_router(paths_router)
app.include_router(blast_radius_router)
app.include_router(chokepoints_router)
app.include_router(prioritization_router)
app.include_router(simulation_router)
app.include_router(optimization_router)
app.include_router(explanation_router)
app.include_router(benchmark_router)
app.include_router(generator_router)
app.include_router(importers_router)
