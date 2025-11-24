# DID WebVH Server Demo

## Prerequisites

### Docker Compose

Ensure you have Docker Compose installed. Verify with:
```bash
docker compose --version
```

Installation instructions: https://docs.docker.com/compose/install/

### ngrok (Optional, for Public Access)

For exposing your local server publicly (e.g., for testing with external services):

1. **Sign up** for a free ngrok account: https://dashboard.ngrok.com/
2. **Get your auth token**: https://dashboard.ngrok.com/get-started/your-authtoken
3. **Set up a static domain**: https://dashboard.ngrok.com/domains

## Quick Start with Magic Script 🪄

The fastest way to get started:

```bash
git clone https://github.com/decentralized-identity/didwebvh-server-py.git
cd didwebvh-server-py/demo
./magic.sh
```

This will:
1. Build and start the DID WebVH server
2. Wait for the server to be healthy
3. Run a load test creating 10 DIDs with credentials and resources
4. Display results and explorer links
5. **Keep the server running** for you to explore

## Magic Script Options

### Basic Usage

```bash
# Quick start (10 DIDs, default settings)
./magic.sh

# Create 50 DIDs
./magic.sh -c 50

# Fast concurrent test (100 DIDs)
./magic.sh -c 100 --concurrent

# Use agent provisioning instead of load test
./magic.sh --agent
```

### Build Options

```bash
# Skip rebuild (fastest, use when no code changes)
./magic.sh --no-rebuild

# Full rebuild without cache (clean slate)
./magic.sh --full-rebuild

# Clean volumes and rebuild
./magic.sh --clean
```

### ngrok Integration

To expose your server publicly with ngrok:

```bash
# Create .env.ngrok file with your credentials
cat > .env.ngrok << EOF
NGROK_TOKEN=your_ngrok_token_here
WEBVH_DOMAIN=your-static-domain.ngrok-free.app
EOF

# Start with ngrok
./magic.sh --ngrok
```

The script will:
- Start ngrok tunnel automatically
- Configure the server to use your public domain
- Display your public URL for external access

### Advanced Options

```bash
# Stop server after test (default: keeps running)
./magic.sh --stop

# Custom number of updates per DID
./magic.sh -c 20 -u 5

# See all available options
./magic.sh --help
```

### Full Options Reference

```
Usage: ./magic.sh [OPTIONS]

Build Options:
  --no-rebuild      Skip Docker rebuild (fastest)
  --full-rebuild    Full rebuild without cache (cleanest)
  --clean           Remove volumes before rebuild

Load Test Options:
  -c, --count N     Number of DIDs to create (default: 10)
  -u, --updates N   Updates per DID (default: 2)
  -s, --server URL  Server URL for load test (default: http://localhost:8000)
                    Use this to test against an existing server instead of starting one
  --concurrent      Run tests concurrently (faster)
  --agent           Use agent provisioning instead of load test

ngrok Options:
  --ngrok           Enable ngrok tunnel for public access
                    Requires NGROK_TOKEN and WEBVH_DOMAIN in .env.ngrok

Server Options:
  --stop            Stop server after test (default: keeps running)

Examples:
  ./magic.sh                          # Quick start with defaults
  ./magic.sh -c 50 --concurrent       # 50 DIDs concurrently
  ./magic.sh -s http://localhost:8000 # Test existing server (skip startup)
  ./magic.sh -s https://did.example.com -c 20  # Test remote server
  ./magic.sh --ngrok                  # Start with ngrok
  ./magic.sh --agent --ngrok          # Agent provisioning with ngrok
  ./magic.sh --no-rebuild -c 20       # Skip rebuild, 20 DIDs
  ./magic.sh --full-rebuild --clean   # Clean rebuild
```

## What Gets Created

After running the magic script, you'll have:

### Services Running

1. **DID WebVH Server** (port 8000)
   - Main server with REST API
   - Explorer UI for browsing DIDs, resources, and credentials
   - Access: `http://localhost:8000`

2. **PostgreSQL Database** (port 5432)
   - Persistent storage for all data
   - Auto-configured and initialized

3. **ACA-Py Agent** (ports 8020/8021) - *with `--agent` flag*
   - Admin API on port 8020
   - Inbound transport on port 8021
   - WebVH plugin enabled
   - Auto-provisioned with witness configuration

4. **Caddy Reverse Proxy** (ports 80/443)
   - Routes requests to appropriate services
   - Handles CORS and security headers

5. **ngrok Tunnel** - *with `--ngrok` flag*
   - Public HTTPS URL for your local server
   - Automatic configuration

### Test Data Created

**With default load test** (`./magic.sh`):
- 10 DIDs with full log history
- 2 updates per DID (configurable)
- Verification methods added to each DID
- WHOIS verifiable presentations
- 1 AnonCreds schema per DID
- 2 verifiable credentials per DID:
  - 1 regular VC with Data Integrity Proof
  - 1 EnvelopedVerifiableCredential (VC-JOSE/JWT)

**With agent provisioning** (`./magic.sh --agent`):
- Agent wallet provisioned
- Witness configuration set up
- DIDs created through agent
- Ready for advanced agent operations

## Exploring the Data

Once the server is running, browse your data:

### Explorer UI

- **DIDs**: `http://localhost:8000/explorer/dids?namespace=loadtest`
- **Credentials**: `http://localhost:8000/explorer/credentials?namespace=loadtest`
- **Resources**: `http://localhost:8000/explorer/resources`
- **Homepage**: `http://localhost:8000/explorer`

### API Endpoints

- **API Docs**: `http://localhost:8000/docs`
- **DID Resolution**: `http://localhost:8000/{namespace}/{identifier}/did.jsonl`
- **WHOIS**: `http://localhost:8000/{namespace}/{identifier}/whois.vp`
- **Resources**: `http://localhost:8000/{namespace}/{identifier}/resources/{resource_id}`
- **Credentials**: `http://localhost:8000/{namespace}/{identifier}/credentials/{credential_id}`

## Load Test Details

### Performance Metrics

The load test reports:
- Total DIDs created (successful/failed)
- Total execution time
- Average time per DID
- Total log entries
- Total resources uploaded
- Total credentials published
- Throughput (DIDs/second)

### Example Output

**Sequential Mode (default):**
```
══════════════════════════════════════════════════════════════════════
Starting Load Test
Server: http://localhost:8000
DIDs to create: 10
Namespace: loadtest
Updates per DID: 2
Total log entries per DID: 4
Run ID: a1b2c3d4
══════════════════════════════════════════════════════════════════════

[1/10] Processing DID a1b2c3d4-0000
✓ Created DID: did:webvh:QmXyz...
  ✓ Update 1 complete
  ✓ Update 2 complete
  ✓ Verification method added
  ✓ WHOIS uploaded
  ✓ Schema uploaded
  ✓ Regular VC published
  ✓ Enveloped VC published

Total DIDs: 10
✓ Successful: 10
Total Time: 48.75s
Avg Time per DID: 4.88s
Throughput: 0.21 DIDs/second
══════════════════════════════════════════════════════════════════════
```

**Concurrent Mode (`--concurrent`):**
```
Running tests concurrently (max 10 at once)...

Progress: 10/10 completed (10 successful)

Total DIDs: 10
✓ Successful: 10
Total Time: 12.34s  ← 4x faster!
Avg Time per DID: 1.23s
Throughput: 0.81 DIDs/second
══════════════════════════════════════════════════════════════════════
```

## Configuration

### Environment Variables

Create a `.env` file in the `demo` directory for custom configuration:

```bash
# Server Configuration
DOMAIN=localhost
WEBVH_API_KEY=webvh

# Witness Configuration
KNOWN_WITNESS_KEY=your_witness_key
KNOWN_WITNESS_REGISTRY=https://witness-registry-url

# WebVH Settings
WEBVH_VERSION=1.0
WEBVH_WITNESS=true
WEBVH_WATCHER=https://did.observer
WEBVH_PREROTATION=true
WEBVH_PORTABILITY=true
WEBVH_ENDORSEMENT=false

# Database
POSTGRES_USER=postgres
POSTGRES_PASSWORD=mysecretpassword
POSTGRES_DB=didwebvh-server
```

### ngrok Configuration

Create a `.env.ngrok` file for ngrok settings:

```bash
NGROK_TOKEN=your_ngrok_token_here
WEBVH_DOMAIN=your-static-domain.ngrok-free.app
```

The magic script will automatically load these when using `--ngrok`.
