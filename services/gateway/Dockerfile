FROM ghcr.io/astral-sh/uv:0.13.8-python3.12-trixie-slim

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_FROZEN=1 PYTHONUNBUFFERED=1

# Workspace metadata first for layer caching, then sources.
COPY pyproject.toml uv.lock ./
COPY packages packages
COPY services services
RUN uv sync --package gateway --no-dev

COPY services/gateway/config /app/config
ENV PATH=/app/.venv/bin:$PATH
EXPOSE 8000
CMD ["uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
