# DID Web with Verifiable History Server Python

A Web Server component for a DID WebVH implementation built with FastAPI.

**DID WebVH Specification**: [https://identity.foundation/didwebvh](https://identity.foundation/didwebvh)

---

## Helm charts have been migrated

**This repository no longer contains Kubernetes or Helm artifacts** (`charts/`, chart packaging, or chart-oriented GitHub Actions). They now live in the DIF Helm charts repository.

| | |
| --- | --- |
| **Charts repository** | [decentralized-identity/helm-charts-dif](https://github.com/decentralized-identity/helm-charts-dif) |
| **Helm repo (add / install)** | `helm repo add dif https://decentralized-identity.github.io/helm-charts-dif` then e.g. `helm install my-release dif/didwebvh-server-py` |

Use that project for chart development, versioning, and releases. This repo is **application source only** (server, demo, docs).

---

## Quick Start

```bash
# Install dependencies
cd server
uv sync

# Copy and configure environment
cp env.example .env
# Edit .env with your settings

# Run server
uv run python main.py
```

The server will be available at `http://localhost:8000` with:
- **API Documentation**: `http://localhost:8000/docs` (Swagger UI)
- **Web Explorer**: `http://localhost:8000/api/explorer`

## Documentation

📚 **Complete documentation is available in the [User Manual](docs/index.md)**

To view the documentation locally:

```bash
# Install Zensical
pip install zensical

# Start the documentation server
zensical serve
```

The documentation will be available at `http://localhost:8000` (or the port specified in `zensical.toml`).

## Additional Resources

- **[Server README](server/README.md)**: Quick setup guide
- **Demo**: See the `demo/` directory for load testing and examples

## License

Apache License 2.0
