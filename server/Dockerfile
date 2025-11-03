FROM python:3.13-slim

ARG user=webvh
ARG home=/home/${user}
ARG uv_cache_dir=${home}/.cache/uv

# Install system dependencies required for psycopg2-binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create user, directories, and set permissions in a single layer
RUN adduser --system --group --home ${home} ${user} && \
    usermod -a -G 0 ${user} && \
    mkdir -p ${home} ${uv_cache_dir}/uv && \
    chown -R ${user}:root ${home} ${uv_cache_dir} && \
    chmod -R ug+rw ${home} ${uv_cache_dir}

# Set environment variables for uv cache (required for OpenShift)
ENV HOME=${home}
ENV UV_CACHE_DIR=${uv_cache_dir}

WORKDIR ${home}

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /uvx /bin/

# Copy dependency files first for better layer caching
COPY --chown=${user}:root README.md pyproject.toml uv.lock ./

# Install dependencies before copying code (better cache utilization)
USER ${user}
RUN uv sync --frozen --no-dev

# Copy application code (this layer changes most frequently)
COPY --chown=${user}:root app ./app
COPY --chown=${user}:root config.py main.py ./

# Run the application using the synced environment
CMD ["uv", "run", "--no-dev", "python", "main.py"]