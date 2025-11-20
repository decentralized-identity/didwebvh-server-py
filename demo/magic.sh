#!/bin/bash
#
# Magic script to start DID WebVH server and run load test
#
# This script will:
# 1. Start the DID WebVH server using Docker Compose
# 2. Wait for the server to be healthy
# 3. Run the load test with configurable parameters
# 4. Display results
# 5. Optionally tear down the server
#
# Usage:
#   ./magic.sh [OPTIONS]
#
# Options:
#   -c, --count <N>      Number of DIDs to create (default: 10)
#   -u, --updates <N>    Number of updates per DID (default: 2)
#   -s, --server <URL>   Server URL for load test (default: http://localhost:8000)
#                        Use this to test against an existing server instead of starting one
#   -k, --api-key <KEY>  API key for admin endpoints (default: env WEBVH_API_KEY or 'webvh')
#   --concurrent         Run load test concurrently (faster)
#   --agent              Use agent provisioning (ACA-Py) instead of load test
#   --stop               Stop server after load test (default: keep running)
#   --no-rebuild         Skip rebuild (default: rebuild with cache)
#   --full-rebuild       Full rebuild without cache (slower)
#   --clean              Clean up existing containers and volumes first
#   --ngrok              Enable ngrok tunnel (requires NGROK_TOKEN and WEBVH_DOMAIN)
#   -h, --help           Show this help message
#
# Examples:
#   ./magic.sh                           # Create 10 DIDs, rebuild with cache
#   ./magic.sh -c 50 --concurrent        # Create 50 DIDs concurrently
#   ./magic.sh -c 100 -u 3 --stop        # Create 100 DIDs, stop server after
#   ./magic.sh -s http://localhost:8000  # Test against existing server (skip startup)
#   ./magic.sh -s https://did.example.com -c 20  # Test remote server
#   ./magic.sh -k my-api-key -c 20       # Use custom API key
#   ./magic.sh --agent                   # Use ACA-Py agent provisioning
#   ./magic.sh --clean --full-rebuild    # Clean full rebuild (no cache)
#   ./magic.sh --ngrok                   # Start with ngrok tunnel
#

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
DID_COUNT=10
UPDATES_PER_DID=2
CONCURRENT_FLAG=""
USE_AGENT=false
KEEP_SERVER=true
REBUILD_FLAG="--build"  # Default: rebuild with cache
REBUILD_NO_CACHE=false
CLEAN_FIRST=false
USE_NGROK=false
SERVER_URL="http://localhost:8000"
INTERNAL_SERVER_URL=""  # Used for load test when ngrok is enabled
NAMESPACE="loadtest"
USE_EXISTING_SERVER=false  # If true, skip Docker Compose startup
API_KEY=""  # API key for admin endpoints (defaults to env var or 'webvh')

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--count)
            DID_COUNT="$2"
            shift 2
            ;;
        -u|--updates)
            UPDATES_PER_DID="$2"
            shift 2
            ;;
        -s|--server)
            SERVER_URL="$2"
            USE_EXISTING_SERVER=true
            shift 2
            ;;
        -k|--api-key)
            API_KEY="$2"
            shift 2
            ;;
        --concurrent)
            CONCURRENT_FLAG="--concurrent"
            shift
            ;;
        --agent)
            USE_AGENT=true
            shift
            ;;
        --stop)
            KEEP_SERVER=false
            shift
            ;;
        --keep)
            # Legacy flag - kept for backwards compatibility
            KEEP_SERVER=true
            shift
            ;;
        --no-rebuild)
            REBUILD_FLAG=""
            shift
            ;;
        --full-rebuild)
            REBUILD_FLAG="--build"
            REBUILD_NO_CACHE=true
            shift
            ;;
        --rebuild)
            # Legacy flag - kept for backwards compatibility (same as default now)
            REBUILD_FLAG="--build"
            shift
            ;;
        --clean)
            CLEAN_FIRST=true
            shift
            ;;
        --ngrok)
            USE_NGROK=true
            shift
            ;;
        -h|--help)
            # Print help and exit
            head -n 30 "$0" | grep "^#" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$PROJECT_ROOT/server"

# Print banner
echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  🪄 DID WebVH Server - Magic Load Test Script"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "${NC}"

# If using existing server, skip Docker Compose startup
if [ "$USE_EXISTING_SERVER" = true ]; then
    echo -e "${YELLOW}⚠ Using existing server: ${SERVER_URL}${NC}"
    echo -e "${YELLOW}  Skipping Docker Compose startup${NC}"
    echo ""
    
    # Wait for server to be ready
    echo -e "${BLUE}Waiting for server to be ready...${NC}"
    MAX_WAIT=60
    WAIT_COUNT=0
    while ! curl -sf "$SERVER_URL/api/server/status" > /dev/null 2>&1; do
        if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
            echo -e "${RED}✗ Server not responding after ${MAX_WAIT}s${NC}"
            echo -e "${RED}  Please ensure the server is running at ${SERVER_URL}${NC}"
            exit 1
        fi
        echo -n "."
        sleep 1
        WAIT_COUNT=$((WAIT_COUNT + 1))
    done
    echo ""
    echo -e "${GREEN}✓ Server is ready!${NC}"
    echo ""
    
    # Set load test URL
    LOAD_TEST_URL="$SERVER_URL"
    export WEBVH_SERVER_URL="$SERVER_URL"
    
    # Skip to load test section
    SKIP_TO_LOAD_TEST=true
else
    SKIP_TO_LOAD_TEST=false
fi

# Display configuration
echo -e "${BLUE}Configuration:${NC}"
echo "  Server URL:      $SERVER_URL"
echo "  DIDs to create:  $DID_COUNT"
echo "  Updates per DID: $UPDATES_PER_DID"
echo "  Namespace:       $NAMESPACE"
echo "  Concurrent:      $([ -n "$CONCURRENT_FLAG" ] && echo "Yes" || echo "No")"
echo "  Rebuild:         $([ -z "$REBUILD_FLAG" ] && echo "Skip" || ( [ "$REBUILD_NO_CACHE" = true ] && echo "Full (no cache)" || echo "With cache" ))"
echo "  Use ngrok:       $USE_NGROK"
echo "  Keep running:    $KEEP_SERVER"
echo ""

# Clean up if requested
if [ "$CLEAN_FIRST" = true ]; then
    echo -e "${YELLOW}🧹 Cleaning up existing containers and volumes...${NC}"
    cd "$SCRIPT_DIR"
    docker compose down -v 2>/dev/null || true
    echo -e "${GREEN}✓ Cleanup complete${NC}"
    echo ""
fi

# Validate ngrok configuration if enabled
if [ "$USE_NGROK" = true ]; then
    # Load .env file if it exists
    if [ -f "$SCRIPT_DIR/.env" ]; then
        echo -e "${CYAN}📄 Loading environment from .env...${NC}"
        set -a  # Automatically export all variables
        source "$SCRIPT_DIR/.env"
        set +a  # Disable auto-export
    fi
    
    # Check for .env.ngrok file (overrides .env if present)
    if [ -f "$SCRIPT_DIR/.env.ngrok" ]; then
        echo -e "${CYAN}📄 Loading ngrok config from .env.ngrok...${NC}"
        source "$SCRIPT_DIR/.env.ngrok"
    fi
    
    if [ -z "${NGROK_TOKEN}" ]; then
        echo -e "${RED}✗ Error: NGROK_TOKEN environment variable is required for ngrok${NC}"
        echo ""
        echo "Options to set it:"
        echo "  1. Add to .env file:        echo 'NGROK_TOKEN=your-token' >> .env"
        echo "  2. Export in your shell:    export NGROK_TOKEN='your-token'"
        echo "  3. Create .env.ngrok file:  cp .env.ngrok.example .env.ngrok"
        echo "  4. Run inline:              NGROK_TOKEN='token' ./magic.sh --ngrok"
        echo ""
        echo "Get your token at: https://dashboard.ngrok.com/get-started/your-authtoken"
        exit 1
    fi
    if [ -z "${WEBVH_DOMAIN}" ]; then
        echo -e "${RED}✗ Error: WEBVH_DOMAIN environment variable is required for ngrok${NC}"
        echo ""
        echo "Options to set it:"
        echo "  1. Add to .env file:        echo 'WEBVH_DOMAIN=your-domain.ngrok-free.app' >> .env"
        echo "  2. Export in your shell:    export WEBVH_DOMAIN='your-domain.ngrok-free.app'"
        echo "  3. Create .env.ngrok file:  cp .env.ngrok.example .env.ngrok"
        echo "  4. Run inline:              WEBVH_DOMAIN='domain' ./magic.sh --ngrok"
        echo ""
        echo "Get your domain at: https://dashboard.ngrok.com/domains"
        exit 1
    fi
    echo -e "${CYAN}🌐 ngrok enabled with domain: ${WEBVH_DOMAIN}${NC}"
    echo ""
    # Set public URL for display and external access
    SERVER_URL="https://${WEBVH_DOMAIN}"
    # Set internal URL for load test (avoids ngrok tunnel overhead)
    INTERNAL_SERVER_URL="http://localhost:8000"
fi

# Skip Docker Compose section if using existing server
if [ "$SKIP_TO_LOAD_TEST" = false ]; then
    # Start the server
    echo -e "${BLUE}🚀 Starting DID WebVH server...${NC}"
    cd "$SCRIPT_DIR"

    # Build with --no-cache if requested (must be separate from 'up' command)
    if [ "$REBUILD_NO_CACHE" = true ]; then
        echo -e "${YELLOW}Building with --no-cache (clean rebuild)...${NC}"
        docker compose build --no-cache
        REBUILD_FLAG=""  # Already built, don't rebuild again in 'up'
    fi

    # Export WEBVH_DOMAIN for docker-compose.yml config substitution
    if [ "$USE_NGROK" = true ]; then
        export WEBVH_DOMAIN="${WEBVH_DOMAIN}"
    else
        # For local/non-ngrok, use localhost
        export WEBVH_DOMAIN="${WEBVH_DOMAIN:-localhost}"
    fi

    # Start with docker compose (include ngrok and/or agent profile if enabled)
    PROFILES=""
    if [ "$USE_NGROK" = true ]; then
        PROFILES="$PROFILES --profile ngrok"
    fi
    if [ "$USE_AGENT" = true ]; then
        PROFILES="$PROFILES --profile agent"
    fi

    if [ -n "$PROFILES" ]; then
        docker compose $PROFILES up -d $REBUILD_FLAG
    else
        docker compose up -d $REBUILD_FLAG
    fi

    # Wait for server to be healthy
    echo -e "${YELLOW}⏳ Waiting for server to be ready...${NC}"
    MAX_WAIT=60
    ELAPSED=0
    while ! curl -sf "$SERVER_URL/api/server/status" > /dev/null 2>&1; do
        if [ $ELAPSED -ge $MAX_WAIT ]; then
            echo -e "${RED}✗ Server failed to start within ${MAX_WAIT}s${NC}"
            echo ""
            echo -e "${YELLOW}📋 Server logs:${NC}"
            docker compose logs --tail=50 webvh-server
            echo ""
            echo -e "${RED}Exiting...${NC}"
            exit 1
        fi
        
        printf "."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done

    echo ""
    echo -e "${GREEN}✓ Server is healthy and ready!${NC}"
    echo ""

    # Show server info
    echo -e "${BLUE}📊 Server Status:${NC}"
    SERVER_STATUS=$(curl -s "$SERVER_URL/api/server/status" | jq -r '.domain // "unknown"')
    echo "  Domain: $SERVER_STATUS"
    echo "  Explorer: ${SERVER_URL}/api/explorer/dids"
    echo "  API Docs: ${SERVER_URL}/docs"

    # Show ngrok info if enabled
    if [ "$USE_NGROK" = true ]; then
        echo ""
        echo -e "${CYAN}🌐 ngrok Tunnel:${NC}"
        echo "  Public URL: ${SERVER_URL}"
        echo "  Internal URL: ${INTERNAL_SERVER_URL} (used by load test)"
        echo "  ngrok Dashboard: https://dashboard.ngrok.com"
    fi
    echo ""
    
    # Set load test URL
    if [ "$USE_NGROK" = true ]; then
        LOAD_TEST_URL="$INTERNAL_SERVER_URL"
        export WEBVH_SERVER_URL="$SERVER_URL"  # Public URL for external references
    else
        LOAD_TEST_URL="$SERVER_URL"
        export WEBVH_SERVER_URL="$SERVER_URL"
    fi
fi  # End of SKIP_TO_LOAD_TEST check

# Run provisioning
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
if [ "$USE_AGENT" = true ]; then
    echo -e "${GREEN}🤖 Running Agent Provisioning${NC}"
else
    echo -e "${GREEN}🧪 Running Load Test${NC}"
fi
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

cd "$SCRIPT_DIR"

# Export environment variables
export WEBVH_NAMESPACE="$NAMESPACE"
# Only set WEBVH_API_KEY if not provided via command line
if [ -z "$API_KEY" ]; then
    export WEBVH_API_KEY="${WEBVH_API_KEY:-webvh}"  # Default API key for witness registration
else
    export WEBVH_API_KEY="$API_KEY"
fi

# Run either agent provisioning or load test
set +e  # Don't exit on error for provisioning/load test
if [ "$USE_AGENT" = true ]; then
    # Wait for agent to be ready
    echo -e "${YELLOW}⏳ Waiting for ACA-Py agent to be ready...${NC}"
    MAX_WAIT=60
    ELAPSED=0
    while ! curl -sf "http://localhost:8020/status" > /dev/null 2>&1; do
        if [ $ELAPSED -ge $MAX_WAIT ]; then
            echo -e "${RED}✗ Agent failed to start within ${MAX_WAIT}s${NC}"
            exit 1
        fi
        printf "."
        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done
    echo ""
    echo -e "${GREEN}✓ Agent is ready!${NC}"
    echo ""
    
    # Run agent provisioning script
    export AGENT_ADMIN_API_URL="http://localhost:8020"
    export AGENT_ADMIN_API_KEY=""
    export WATCHER_URL=""  # Optional
    export WATCHER_API_KEY=""  # Optional
    
    # Use the public URL for agent configuration (goes into DIDs)
    # Agent will communicate with server via Docker network internally
    if [ "$USE_NGROK" = true ]; then
        export WEBVH_SERVER_URL="https://${WEBVH_DOMAIN}"
    else
        export WEBVH_SERVER_URL="http://localhost:8000"
    fi
    
    echo -e "${CYAN}Agent Configuration:${NC}"
    echo "  Admin API: ${AGENT_ADMIN_API_URL}"
    echo "  WebVH Server URL: ${WEBVH_SERVER_URL}"
    echo "  (DIDs will use this domain)"
    echo ""
    
    uv run python load_test_agent.py
    LOAD_TEST_EXIT_CODE=$?
else
    # Run the load test from demo directory with its own dependencies
    if [ -n "$API_KEY" ]; then
        uv run python load_test.py \
            --count "$DID_COUNT" \
            --updates "$UPDATES_PER_DID" \
            --server "$LOAD_TEST_URL" \
            --namespace "$NAMESPACE" \
            --api-key "$API_KEY" \
            $CONCURRENT_FLAG
    else
        uv run python load_test.py \
            --count "$DID_COUNT" \
            --updates "$UPDATES_PER_DID" \
            --server "$LOAD_TEST_URL" \
            --namespace "$NAMESPACE" \
            $CONCURRENT_FLAG
    fi
    LOAD_TEST_EXIT_CODE=$?
fi
set -e

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"

# Show where to view results
if [ $LOAD_TEST_EXIT_CODE -eq 0 ]; then
    if [ "$USE_AGENT" = true ]; then
        echo -e "${GREEN}✓ Agent provisioning completed successfully!${NC}"
    else
        echo -e "${GREEN}✓ Load test completed successfully!${NC}"
    fi
    echo ""
    if [ "$USE_EXISTING_SERVER" = true ]; then
        # Using existing server, just show results
        echo -e "${CYAN}📊 View Results:${NC}"
        echo ""
        echo "  DIDs:        ${SERVER_URL}/api/explorer/dids?namespace=${NAMESPACE}"
        echo "  Resources:   ${SERVER_URL}/api/explorer/resources"
        echo "  Credentials: ${SERVER_URL}/api/explorer/credentials?namespace=${NAMESPACE}"
        echo ""
    else
        echo -e "${BLUE}📊 View Results:${NC}"
        echo "  DIDs:        ${SERVER_URL}/api/explorer/dids?namespace=${NAMESPACE}"
        echo "  Resources:   ${SERVER_URL}/api/explorer/resources"
        echo "  Credentials: ${SERVER_URL}/api/explorer/credentials?namespace=${NAMESPACE}"
        echo ""
        
        # Calculate expected credentials
        EXPECTED_CREDS=$((DID_COUNT * 2))
        echo -e "${GREEN}Expected credentials: ${EXPECTED_CREDS} \(${DID_COUNT} regular + ${DID_COUNT} enveloped\)${NC}"
    fi
else
    echo -e "${RED}✗ Load test failed with exit code: $LOAD_TEST_EXIT_CODE${NC}"
    echo ""
    echo -e "${YELLOW}📋 Check server logs:${NC}"
    echo "  docker compose -f $SCRIPT_DIR/docker-compose.yml logs webvh-server"
fi

echo ""

# Decide whether to keep server running (only if we started it)
if [ "$USE_EXISTING_SERVER" = true ]; then
    # Using existing server, nothing to stop
    echo -e "${GREEN}✓ Load test complete. Server remains running.${NC}"
    echo ""
elif [ "$KEEP_SERVER" = true ]; then
    echo -e "${GREEN}🎉 Server is still running!${NC}"
    echo ""
    echo -e "${BLUE}Useful commands:${NC}"
    echo "  View logs:       cd $SCRIPT_DIR && docker compose logs -f webvh-server"
    echo "  Stop server:     cd $SCRIPT_DIR && docker compose down"
    echo "  Restart server:  cd $SCRIPT_DIR && docker compose restart"
    echo "  Clean up:        cd $SCRIPT_DIR && docker compose down -v"
    echo ""
    echo -e "${CYAN}Explorer URLs:${NC}"
    echo "  ${SERVER_URL}/api/explorer/dids"
    echo "  ${SERVER_URL}/api/explorer/resources"
    echo "  ${SERVER_URL}/api/explorer/credentials"
else
    echo -e "${YELLOW}🛑 Stopping server...${NC}"
    cd "$SCRIPT_DIR"
    docker compose down
    echo -e "${GREEN}✓ Server stopped${NC}"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Done!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"

exit $LOAD_TEST_EXIT_CODE

