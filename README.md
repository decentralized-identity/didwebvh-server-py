# DID Web with Verifiable History Server Python

A Web Server component for a DID WebVH implementation built with FastAPI.

**DID WebVH Specification**: [https://identity.foundation/didwebvh](https://identity.foundation/didwebvh)

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
