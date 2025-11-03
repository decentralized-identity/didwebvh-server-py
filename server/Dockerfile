FROM python:3.13-slim

# Install system dependencies required for psycopg2-binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create user and directory
RUN addgroup --system webvh_user && \
    adduser --system --group --home /home/webvh_user webvh_user && \
    mkdir -p /didwebvh-server-py && \
    chown webvh_user:webvh_user /didwebvh-server-py

WORKDIR /didwebvh-server-py

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /uvx /bin/

# Copy dependency files first for better layer caching
COPY --chown=webvh_user:webvh_user README.md pyproject.toml uv.lock ./

# Install dependencies before copying code (better cache utilization)
USER webvh_user
RUN uv sync --frozen --no-dev --directory /didwebvh-server-py

# Copy application code
COPY --chown=webvh_user:webvh_user app ./app
COPY --chown=webvh_user:webvh_user config.py main.py ./

# Run the application using the synced environment
CMD ["uv", "run", "--no-dev", "python", "main.py"]