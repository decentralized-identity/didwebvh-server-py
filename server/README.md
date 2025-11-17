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

Create a `.env` file in the `server` directory (see `env.example` for all options):

### Required Configuration
```env
WEBVH_DOMAIN=did.example.org
WEBVH_ADMIN_API_KEY=your-secret-key
```

### Policy Configuration
```env
WEBVH_VERSION=1.0
WEBVH_WITNESS=true
WEBVH_WATCHER=https://watcher.example.com  # Optional
WEBVH_PORTABILITY=true
WEBVH_PREROTATION=true
WEBVH_ENDORSEMENT=true
```

### Witness Configuration (Optional)
```env
WEBVH_WITNESS_ID=did:key:z6Mk...
WEBVH_WITNESS_INVITATION=https://witness.example.com/oob-invite?oob=...
```

### Database Configuration
```env
# Option 1: SQLite (default)
# No configuration needed

# Option 2: PostgreSQL
POSTGRES_URL=postgresql://user:password@host:port/database
# OR use individual components:
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
POSTGRES_SERVER_NAME=localhost
POSTGRES_SERVER_PORT=5432
```

See `env.example` for a complete list of all configuration options.

## API Endpoints

### Server Endpoints
- `GET /` - Root endpoint (DID path requests, invitation lookup, or explorer redirect)
- `GET /.well-known/did.json` - Server DID document with witness services
- `GET /server/status` - Server status and health

### Identifier Endpoints
- `GET /?namespace={namespace}&alias={alias}` - Request DID creation parameters
- `POST /{namespace}/{alias}` - Create or update DID with log entry
- `GET /{namespace}/{alias}/did.json` - Resolve DID document
- `GET /{namespace}/{alias}/did.jsonl` - Get DID log history
- `GET /{namespace}/{alias}/did-witness.json` - Get witness file
- `GET /{namespace}/{alias}/whois.vp` - Get WHOIS presentation

### Resource Endpoints
- `POST /{namespace}/{alias}/resources` - Upload attested resource
- `PUT /{namespace}/{alias}/resources/{resource_id}` - Update resource metadata
- `GET /{namespace}/{alias}/resources/{resource_id}` - Get specific resource
- `GET /{namespace}/{alias}/resources` - List all resources for a DID

### Credential Endpoints
- `POST /{namespace}/{alias}/credentials` - Upload verifiable credential
- `GET /{namespace}/{alias}/credentials` - List credentials for a DID

### Admin Endpoints
- `POST /admin/witnesses` - Add known witness
- `DELETE /admin/witnesses/{witness_id}` - Remove witness
- `GET /admin/parameters` - Get current policy parameters
- `POST /admin/tasks` - Start admin tasks (hidden from Swagger)

### Explorer Endpoints
- `GET /explorer` - Main explorer interface
- `GET /explorer/dids` - DID explorer
- `GET /explorer/resources` - Resource explorer
- `GET /explorer/witnesses` - Witness network explorer

### Tails Server (if enabled)
- `GET /tails/{rev_reg_id}` - Get revocation registry tails file

## Key Concepts

### Roles
- **Admin**: Manages server policies and witness registry
- **Witness**: Signs DID operations and endorses resources/credentials
- **Controller**: Creates and manages DIDs, publishes resources
- **Watcher**: Optional monitoring service for DID operations

### Policy Enforcement
The server enforces policies configured via environment variables:
- **Witness Requirements**: Requires witness signatures for DID operations
- **Endorsement**: Requires witness endorsement for resources and credentials
- **Portability**: Enforces portability in DID parameters
- **Prerotation**: Requires next key hashes for key rotation
- **Watcher**: Includes watcher URLs in DID parameters

### Witness Registry
Witnesses must be registered via the admin API before they can sign operations. Registered witnesses are advertised in the server's DID document as `WitnessInvitation` services.

## Documentation

Comprehensive documentation is available in the `/docs` directory:

- **User Manual**: Complete guide with multiple sections
  - Introduction and Roles
  - Getting Started and Configuration
  - API Endpoints and Protocols
  - Admin Operations and DID Operations
  - AnonCreds Support
  - Examples

- **API Documentation**: Interactive Swagger UI at `/docs` when server is running

- **Project README**: See `../README.md` for project overview and architecture

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