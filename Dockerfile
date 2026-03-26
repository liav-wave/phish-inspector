FROM python:3.11-slim

# Don't run as root
RUN useradd --create-home appuser

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /home/appuser/app

# Copy dependency files first (layer caching)
COPY pyproject.toml uv.lock ./

# Install dependencies with locked versions
RUN uv sync --frozen

# Copy application code
COPY src/ ./src/
COPY tests/ ./tests/

# Switch to non-root user
USER appuser

# Default: run MCP server in stdio mode
CMD ["uv", "run", "python", "-m", "phish_triage.server"]
