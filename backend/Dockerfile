# Backend image: FastAPI + Uvicorn (production, non-root user).
# Build context is the repository root: docker build -f backend/Dockerfile .
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Create non-root group and user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy package and setup permissions
COPY backend/ ./backend/
RUN mkdir -p /data && chown -R appuser:appgroup /app /data

USER appuser

EXPOSE 8000

# Lifespan in main.py handles database schema creation and idempotent seed data automatically
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
