FROM python:3.11-slim

# Don't run as root
RUN useradd --create-home appuser

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /home/appuser/app

# Copy dependency files first (layer caching)
COPY pyproject.toml uv.lock ./

# Export locked deps and install into system Python (no venv writes at runtime)
RUN uv export --frozen --no-hashes --no-dev > requirements.txt && \
    uv pip install --system -r requirements.txt

# Copy and install the project itself
COPY src/ ./src/
RUN uv pip install --system --no-deps .

# Switch to non-root user
USER appuser

EXPOSE 8080

# Run MCP server in HTTP mode (Cloud Run injects PORT env var)
CMD ["python", "-m", "phish_triage", "http"]
