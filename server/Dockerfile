FROM python:3.12-slim

WORKDIR /fastapi

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy dependency files
COPY pyproject.toml README.md ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY app ./app
COPY config.py main.py ./

# Run the application using the synced environment (no reinstall on startup)
CMD ["uv", "run", "python", "main.py"]