# Build from the REPO ROOT, not this directory:
#   docker build -f backend/Dockerfile -t ecdat-backend .
# (docker-compose.yml does this automatically). This is required because
# the app resolves knowledge-base/ and demo-data/ as siblings of backend/
# at runtime (see app/core/config.py, app/crypto/knowledge_base.py).
FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY knowledge-base/ knowledge-base/
COPY demo-data/ demo-data/

RUN mkdir -p /data
ENV DATABASE_URL=sqlite:////data/ecdat.db

WORKDIR /app/backend
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
