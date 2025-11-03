FROM python:3.13-slim

ARG user=webvh
ARG home=/home/${user}
ARG uv_cache_dir=${home}/.cache/uv

# Install system dependencies required for psycopg2-binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create user and groups
RUN adduser --system --group --home ${home} ${user} && \
    usermod -a -G 0 ${user}

# Set environment variables for uv cache (required for OpenShift)
ENV HOME=${home} \
    UV_CACHE_DIR=${uv_cache_dir}

WORKDIR ${home}

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /uvx /bin/

# Copy dependency files first for better layer caching
COPY --chown=${user}:root README.md pyproject.toml uv.lock ./

# Install dependencies before copying code
USER ${user}
RUN uv sync --no-dev && \
    (uv pip list 2>/dev/null | grep -q psycopg2-binary || uv pip install "psycopg2-binary>=2.9.11")

# Fix permissions for files created by uv sync (OpenShift compatibility)
USER root
RUN chown -R ${user}:root ${home} ${uv_cache_dir} && \
    chmod -R ug+rw ${home} ${uv_cache_dir}

# Copy application code (this layer changes most frequently)
COPY --chown=${user}:root app ./app
COPY --chown=${user}:root config.py main.py ./

USER ${user}

# Run the application using the synced environment
CMD ["uv", "run", "--no-dev", "python", "main.py"]