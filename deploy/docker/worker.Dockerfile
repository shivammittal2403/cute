# Kept in sync with ../../Dockerfile.worker (single-source via CI check planned).
FROM python:3.12-slim
WORKDIR /app
CMD ["python", "-m", "traceatlas", "worker"]
