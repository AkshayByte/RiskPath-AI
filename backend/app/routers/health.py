"""Health check router."""

from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "cybersecurity-remediation-prioritization"}
