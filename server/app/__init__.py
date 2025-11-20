import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, Request, Query, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.routers import admin, identifiers, resources, credentials, explorer, tails, invitations
from app.plugins.storage import StorageManager
from app.plugins import DidWebVH
from app.plugins.invitations import (
    decode_invitation_from_url,
    build_short_invitation_url,
)
from config import settings
from app.utilities import build_witness_services, timestamp

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup: Ensure database is provisioned (skip in test mode)
    if not os.getenv("PYTEST_CURRENT_TEST"):
        logger.info("Provisioning database on startup...")
        storage = StorageManager()
        await storage.provision()
        logger.info("Database provisioned successfully")

        # Always update policy from environment variables on startup
        logger.info("Applying policy from environment variables...")
        policy_data = {
            "version": settings.WEBVH_VERSION,
            "witness": settings.WEBVH_WITNESS,
            "watcher": settings.WEBVH_WATCHER,
            "portability": settings.WEBVH_PORTABILITY,
            "prerotation": settings.WEBVH_PREROTATION,
            "endorsement": settings.WEBVH_ENDORSEMENT,
            "witness_registry_url": None,
        }
        storage.create_or_update_policy("active", policy_data)
        logger.info(f"Policy {policy_data['version']} applied successfully")

        # Register initial witness from environment variables if provided
        if settings.WEBVH_WITNESS_ID and settings.WEBVH_WITNESS_INVITATION:
            logger.info("Registering initial witness from environment variables...")
            try:
                # Decode invitation to get label
                invitation_payload = decode_invitation_from_url(settings.WEBVH_WITNESS_INVITATION)

                # Validate invitation goal_code and goal
                goal_code = invitation_payload.get("goal_code")
                goal = invitation_payload.get("goal")

                if goal_code != "witness-service":
                    raise ValueError(
                        f"Invalid invitation goal_code. "
                        f"Expected 'witness-service', got '{goal_code}'"
                    )

                if goal != settings.WEBVH_WITNESS_ID:
                    raise ValueError(
                        f"Invitation goal does not match witness ID. "
                        f"Expected '{settings.WEBVH_WITNESS_ID}', got '{goal}'"
                    )

                invitation_label = invitation_payload.get("label") or "Default Server Witness"

                # Build short service endpoint
                short_service_endpoint = build_short_invitation_url(
                    settings.WEBVH_WITNESS_ID, invitation_payload
                )

                # Get or create registry
                registry = storage.get_registry("knownWitnesses")
                if registry:
                    registry_data = registry.registry_data
                    meta = {"updated": timestamp()}
                else:
                    registry_data = {}
                    meta = {"created": timestamp(), "updated": timestamp()}

                # Update or add witness entry
                registry_data[settings.WEBVH_WITNESS_ID] = {
                    "name": invitation_label,
                    "serviceEndpoint": short_service_endpoint,
                }

                # Update registry in database
                storage.create_or_update_registry(
                    registry_id="knownWitnesses",
                    registry_type="witnesses",
                    registry_data=registry_data,
                    meta=meta,
                )

                # Store invitation
                storage.create_or_update_witness_invitation(
                    witness_did=settings.WEBVH_WITNESS_ID,
                    invitation_url=settings.WEBVH_WITNESS_INVITATION,
                    invitation_payload=invitation_payload,
                    invitation_id=invitation_payload.get("@id"),
                    label=invitation_label,
                )

                logger.info(f"Initial witness {settings.WEBVH_WITNESS_ID} registered successfully")
            except Exception as e:
                logger.warning(f"Failed to register initial witness: {e}")
    yield
    # Shutdown: cleanup if needed
    if not os.getenv("PYTEST_CURRENT_TEST"):
        logger.info("Shutting down application...")


app = FastAPI(title=settings.PROJECT_TITLE, version=settings.PROJECT_VERSION, lifespan=lifespan)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_router = APIRouter()
storage = StorageManager()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Error handling debug."""
    exc_str = f"{exc}".replace("\n", " ").replace("   ", " ")
    logging.error(f"{request}: {exc_str}")
    content = {"status_code": 10422, "message": exc_str, "data": None}
    return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)


@api_router.get("/", tags=["Server"])
async def root_endpoint(
    namespace: str = Query(None),
    alias: str = Query(None),
):
    """Root endpoint - handles DID path requests or redirects to explorer."""
    # Handle DID path request
    if namespace and alias:
        # Get policy and registry
        policy = storage.get_policy("active")
        registry = storage.get_registry("knownWitnesses")

        policy_data = policy.to_dict() if policy else {}
        registry_data = registry.registry_data if registry else {}

        webvh = DidWebVH(active_policy=policy_data, active_registry=registry_data)

        # Check if DID already exists
        if storage.get_did_controller_by_alias(namespace, alias):
            raise HTTPException(status_code=409, detail="Alias already exists")

        # Check reserved namespaces
        if namespace in settings.RESERVED_NAMESPACES:
            raise HTTPException(status_code=400, detail=f"Namespace '{namespace}' is reserved")

        # Generate parameters
        parameters = webvh.parameters()
        placeholder_id = webvh.placeholder_id(namespace, alias)

        # Create initial state
        state = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": placeholder_id,
        }

        return JSONResponse(
            status_code=200,
            content={
                "versionId": settings.SCID_PLACEHOLDER,
                "versionTime": timestamp(),
                "parameters": parameters,
                "state": state,
                "proof": webvh.proof_options(),
            },
        )

    # Default: redirect to explorer
    return RedirectResponse(url="/api/explorer", status_code=307)


@api_router.get("/.well-known/did.json", tags=["Resolvers"])
async def well_known_did_document():
    """Expose a DID Web document representing the server."""
    did = f"did:web:{settings.DOMAIN}"
    storage = StorageManager()
    registry = storage.get_registry("knownWitnesses")
    witness_services = build_witness_services(registry) if registry else []
    document = {
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "service": witness_services,
    }

    return JSONResponse(status_code=200, content=document)


# API routes (under /api prefix)
api_router.include_router(explorer.router, prefix="/api/explorer")
api_router.include_router(admin.router, prefix="/api/admin")
api_router.include_router(invitations.router, prefix="/api/invitations")
api_router.include_router(tails.router, prefix="/api/tails", tags=["Tails"])


# Add server status endpoint under /api
@api_router.get("/api/server/status", tags=["Server"])
async def server_status():
    """Server status endpoint."""
    return JSONResponse(status_code=200, content={"status": "ok", "domain": settings.DOMAIN})


# Identifier routes (stay at root - these are DID paths)
api_router.include_router(identifiers.resolver_router)
api_router.include_router(identifiers.router)
api_router.include_router(credentials.router)
api_router.include_router(resources.router)

app.include_router(api_router)
