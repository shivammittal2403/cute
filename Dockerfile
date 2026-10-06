FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
RUN pip install --upgrade uv && uv pip install --system -e .
COPY traceatlas ./traceatlas
COPY sources ./sources
EXPOSE 8000
CMD ["uvicorn", "traceatlas.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
