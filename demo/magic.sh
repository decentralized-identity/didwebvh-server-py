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
#   --concurrent         Run load test concurrently (faster)
#   --stop               Stop server after load test (default: keep running)
#   --no-rebuild         Skip rebuild (default: rebuild with cache)
#   --full-rebuild       Full rebuild without cache (slower)
#   --clean              Clean up existing containers and volumes first
#   -h, --help           Show this help message
#
# Examples:
#   ./magic.sh                           # Create 10 DIDs, rebuild with cache
#   ./magic.sh -c 50 --concurrent        # Create 50 DIDs concurrently
#   ./magic.sh -c 100 -u 3 --stop        # Create 100 DIDs, stop server after
#   ./magic.sh --clean --full-rebuild    # Clean full rebuild (no cache)
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
KEEP_SERVER=true
REBUILD_FLAG="--build"  # Default: rebuild with cache
CLEAN_FIRST=false
SERVER_URL="http://localhost:8000"
NAMESPACE="loadtest"

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
        --concurrent)
            CONCURRENT_FLAG="--concurrent"
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
            REBUILD_FLAG="--build --no-cache"
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

# Display configuration
echo -e "${BLUE}Configuration:${NC}"
echo "  Server URL:      $SERVER_URL"
echo "  DIDs to create:  $DID_COUNT"
echo "  Updates per DID: $UPDATES_PER_DID"
echo "  Namespace:       $NAMESPACE"
echo "  Concurrent:      $([ -n "$CONCURRENT_FLAG" ] && echo "Yes" || echo "No")"
echo "  Rebuild:         $([ -z "$REBUILD_FLAG" ] && echo "Skip" || ( [ "$REBUILD_FLAG" = "--build" ] && echo "With cache" || echo "Full (no cache)" ))"
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

# Start the server
echo -e "${BLUE}🚀 Starting DID WebVH server...${NC}"
cd "$SCRIPT_DIR"

# Start with docker compose
docker compose up -d $REBUILD_FLAG

# Wait for server to be healthy
echo -e "${YELLOW}⏳ Waiting for server to be ready...${NC}"
MAX_WAIT=60
ELAPSED=0
while ! curl -sf "$SERVER_URL/server/status" > /dev/null 2>&1; do
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
SERVER_STATUS=$(curl -s "$SERVER_URL/server/status" | jq -r '.domain // "unknown"')
echo "  Domain: $SERVER_STATUS"
echo "  Explorer: ${SERVER_URL}/explorer/dids"
echo "  API Docs: ${SERVER_URL}/docs"
echo ""

# Run the load test
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🧪 Running Load Test${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

cd "$SCRIPT_DIR"

# Export environment variables for the load test
export WEBVH_SERVER_URL="$SERVER_URL"
export WEBVH_NAMESPACE="$NAMESPACE"
export API_KEY="webvh"  # Default API key for witness registration

# Run the load test from demo directory with its own dependencies
set +e  # Don't exit on error for load test
uv run python load_test.py \
    --count "$DID_COUNT" \
    --updates "$UPDATES_PER_DID" \
    --server "$SERVER_URL" \
    --namespace "$NAMESPACE" \
    $CONCURRENT_FLAG

LOAD_TEST_EXIT_CODE=$?
set -e

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════════${NC}"

# Show where to view results
if [ $LOAD_TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Load test completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}📊 View Results:${NC}"
    echo "  DIDs:        ${SERVER_URL}/explorer/dids?namespace=${NAMESPACE}"
    echo "  Resources:   ${SERVER_URL}/explorer/resources"
    echo "  Credentials: ${SERVER_URL}/explorer/credentials?namespace=${NAMESPACE}"
    echo ""
    
    # Calculate expected credentials
    EXPECTED_CREDS=$((DID_COUNT * 2))
    echo -e "${GREEN}Expected credentials: ${EXPECTED_CREDS} (${DID_COUNT} regular + ${DID_COUNT} enveloped)${NC}"
else
    echo -e "${RED}✗ Load test failed with exit code: $LOAD_TEST_EXIT_CODE${NC}"
    echo ""
    echo -e "${YELLOW}📋 Check server logs:${NC}"
    echo "  docker compose -f $SCRIPT_DIR/docker-compose.yml logs webvh-server"
fi

echo ""

# Decide whether to keep server running
if [ "$KEEP_SERVER" = true ]; then
    echo -e "${GREEN}🎉 Server is still running!${NC}"
    echo ""
    echo -e "${BLUE}Useful commands:${NC}"
    echo "  View logs:       cd $SCRIPT_DIR && docker compose logs -f webvh-server"
    echo "  Stop server:     cd $SCRIPT_DIR && docker compose down"
    echo "  Restart server:  cd $SCRIPT_DIR && docker compose restart"
    echo "  Clean up:        cd $SCRIPT_DIR && docker compose down -v"
    echo ""
    echo -e "${CYAN}Explorer URLs:${NC}"
    echo "  ${SERVER_URL}/explorer/dids"
    echo "  ${SERVER_URL}/explorer/resources"
    echo "  ${SERVER_URL}/explorer/credentials"
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

