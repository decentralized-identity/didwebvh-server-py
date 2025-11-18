# Getting Started

## Installation

1. Clone the repository
2. Install dependencies using `uv`:
   ```bash
   cd server
   uv sync
   ```

3. Copy the example environment file:
   ```bash
   cp env.example .env
   ```

4. Configure your environment variables (see [Configuration](configuration.md))

5. Start the server:
   ```bash
   uv run uvicorn app:app --host 0.0.0.0 --port 8000
   ```

## Quick Start

The server will be available at `http://localhost:8000` (or your configured domain). You can:

- Access the API documentation at `http://localhost:8000/docs`
- Access the explorer UI at `http://localhost:8000/explorer`
- Check server status at `http://localhost:8000/server/status`





