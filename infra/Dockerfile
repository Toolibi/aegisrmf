# Not built in the authoring environment (no Docker daemon available); see README "Verification status".
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 aegis
WORKDIR /app
COPY backend/pyproject.toml ./
COPY backend/aegisrmf ./aegisrmf
COPY backend/alembic ./alembic
COPY backend/alembic.ini ./
COPY LICENSE ./LICENSE
RUN pip install --no-cache-dir .
USER 10001
EXPOSE 8000 8001
CMD ["uvicorn", "aegisrmf.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
