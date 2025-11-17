# DID WebVH Server

A comprehensive DID WebVH (Decentralized Identifier Web Verifiable History) server implementation with web explorer interface.

## Features

- **DID Management**: Create, resolve, and manage DIDs with WebVH method
- **Resource Management**: Upload and manage attested resources (AnonCreds schemas, credential definitions, etc.)
- **Witness Registry**: Manage known witness services and their invitation URLs
- **Policy Enforcement**: Configurable policies for witness requirements, portability, prerotation, and endorsement
- **Web Explorer**: Interactive web interface for browsing DIDs, resources, and witness network
- **AnonCreds Support**: Publish and resolve AnonCreds objects as Attested Resources
- **Multiple Storage**: Support for SQLite and PostgreSQL backends
- **Customizable Branding**: Configurable UI themes and branding

## Quick Start

### Using uv
```bash
# Install dependencies
cd server
uv sync

# Copy example environment file
cp env.example .env

# Edit .env with your configuration
# Then run server
uv run python main.py
```

### Using Docker
```bash
docker build -t didwebvh-server .
docker run -p 8000:8000 \
  -e WEBVH_DOMAIN=did.example.org \
  -e WEBVH_ADMIN_API_KEY=your-secret-key \
  didwebvh-server
```

## Configuration

Create a `.env` file in the `server` directory. See `env.example` for all available options.

**Minimum required configuration:**
```env
WEBVH_DOMAIN=did.example.org
WEBVH_ADMIN_API_KEY=your-secret-key
```

For complete configuration details, see the [Configuration Guide](../docs/content/configuration.md) in the user manual.

## API Endpoints

For complete API documentation, see:
- **[API Endpoints Guide](../docs/content/api-endpoints.md)** - Detailed endpoint reference
- **Swagger UI** - Interactive API docs at `/docs` when server is running

**Quick reference:**
- `GET /` - Root endpoint (DID requests, invitation lookup, explorer)
- `GET /?namespace={ns}&alias={alias}` - Request DID parameters
- `POST /{namespace}/{alias}` - Create/update DID
- `GET /{namespace}/{alias}/did.json` - Resolve DID
- `POST /{namespace}/{alias}/resources` - Upload resource
- `POST /admin/witnesses` - Manage witnesses
- `GET /explorer` - Web explorer interface

## Documentation

📚 **See the [User Manual](../docs/content/index.md) for comprehensive documentation:**

- Getting Started & Configuration
- API Endpoints & Protocols  
- Roles (Admin, Witness, Controller, Watcher)
- Admin Operations & DID Operations
- AnonCreds Support
- Examples

**Interactive API Docs**: Swagger UI at `/docs` when server is running

## Development

### Running Tests
```bash
cd server
uv run pytest
```

### Code Structure
```
server/
├── app/
│   ├── routers/      # API route handlers
│   ├── plugins/      # Core plugins (didwebvh, storage, invitations)
│   ├── models/       # Data models and schemas
│   ├── db/           # Database models and storage
│   └── templates/    # Jinja2 templates for explorer UI
├── config.py         # Configuration settings
├── main.py           # Application entry point
└── env.example        # Example environment file
```

## License

Apache License 2.0