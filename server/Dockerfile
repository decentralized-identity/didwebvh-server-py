FROM python:3.13-slim

ARG user=webvh
ARG home=/home/${user}
ARG uv_cache_dir=${home}/.cache

# Install system dependencies required for psycopg2-binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create user and directory
RUN adduser --system --group --home ${home} ${user}
RUN usermod -a -G 0 ${user} && \
    mkdir -p ${home} && \
    chown -R ${user}:${user} ${home}

WORKDIR ${home}

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /uvx /bin/

# Copy dependency files first for better layer caching
COPY --chown=${user}:${user} README.md pyproject.toml uv.lock ./

# Install dependencies before copying code (better cache utilization)
USER ${user}
RUN uv sync --frozen --no-dev

# Copy application code
COPY --chown=${user}:${user} app ./app
COPY --chown=${user}:${user} config.py main.py ./

USER root

# Set permissions for OpenShift compatibility
RUN mkdir -p ${uv_cache_dir} && \
    chown -R $user:root ${uv_cache_dir} && \
    chmod -R ug+rw ${uv_cache_dir}

USER ${user}

# Run the application using the synced environment
CMD ["uv", "run", "--no-dev", "python", "main.py"]