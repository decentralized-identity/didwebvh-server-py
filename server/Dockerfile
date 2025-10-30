FROM python:3.12-slim

WORKDIR /didwebvh-server-py

# Install system dependencies required for psycopg2-binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml README.md uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY app ./app
COPY config.py main.py ./

# Run the application using the synced environment (no reinstall on startup)
CMD ["uv", "run", "python", "main.py"]