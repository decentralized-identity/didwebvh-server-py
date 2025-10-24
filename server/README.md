# DID WebVH Server

A comprehensive DID WebVH (Decentralized Identifier Web Verifiable History) server implementation with web explorer interface.

## Features

- **DID Management**: Create, resolve, and manage DIDs with WebVH method
- **Resource Management**: Upload and manage attested resources (schemas, credential definitions, etc.)
- **Web Explorer**: Interactive web interface for browsing DIDs and resources
- **Admin Tasks**: Background task system for migrations, load testing, and maintenance
- **Multiple Storage**: Support for SQLite and PostgreSQL backends
- **Theming**: Customizable branding and themes (including Halloween theme!)

## Quick Start

### Using Docker
```bash
docker build -t didwebvh-server .
docker run -p 8000:8000 didwebvh-server
```

### Using uv
```bash
# Install dependencies
uv sync

# Run server
uv run python main.py
```

## Configuration

Set environment variables or create a `.env` file:

```env
DOMAIN=localhost
API_KEY=your-secret-key
DATABASE_URL=sqlite:///app.db
WEBVH_VERSION=1.0
WEBVH_WITNESS=true
```

## API Endpoints

- `GET /` - Web explorer interface
- `GET /dids` - DID explorer
- `GET /resources` - Resource explorer
- `POST /dids` - Create DID
- `GET /dids/{did}` - Resolve DID
- `POST /resources` - Upload resource
- `POST /admin/tasks` - Start admin tasks

## Admin Tasks

- **Migration**: `migrate_askar_to_postgres` - Migrate from Askar to PostgreSQL
- **Load Testing**: `load_test` - Performance testing
- **Sync Records**: `sync_records` - Sync explorer records

## Documentation

See `/docs` directory for detailed documentation:
- `README.md` - Complete user guide
- `ANONCREDS.md` - AnonCreds integration details
- `SQLALCHEMY_STORAGE.md` - Database implementation

## License

Apache License 2.0