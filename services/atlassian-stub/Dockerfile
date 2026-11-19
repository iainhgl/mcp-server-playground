FROM ghcr.io/astral-sh/uv:0.13.8-python3.12-trixie-slim

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_FROZEN=1 PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
COPY packages packages
COPY services services
RUN uv sync --package atlassian-stub --no-dev

ENV PATH=/app/.venv/bin:$PATH
EXPOSE 2990
CMD ["sh", "-c", "uvicorn atlassian_stub.app:app --host 0.0.0.0 --port ${PORT:-2990} --proxy-headers --forwarded-allow-ips '*'"]
