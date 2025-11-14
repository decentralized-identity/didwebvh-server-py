import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, Request, status, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.routers import admin, identifiers, resources, credentials, explorer, tails
from app.plugins.storage import StorageManager
from config import settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup: Ensure database is provisioned (skip in test mode)
    if not os.getenv("PYTEST_CURRENT_TEST"):
        logger.info("Provisioning database on startup...")
        await StorageManager().provision()
        logger.info("Database provisioned successfully")
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


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Error handling debug."""
    exc_str = f"{exc}".replace("\n", " ").replace("   ", " ")
    logging.error(f"{request}: {exc_str}")
    content = {"status_code": 10422, "message": exc_str, "data": None}
    return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_CONTENT)


@api_router.get("/server/status", tags=["Server"], include_in_schema=False)
async def server_status():
    """Server status endpoint."""
    return JSONResponse(status_code=200, content={"status": "ok", "domain": settings.DOMAIN})


@api_router.get("/.well-known/witness.json", tags=["Witness"])
async def well_known_witness_registry():
    """Expose the known witness registry in a well-known location."""
    storage = StorageManager()
    registry = storage.get_registry("knownWitnesses")

    if not registry:
        raise HTTPException(status_code=404, detail="Witness registry not found.")

    return JSONResponse(status_code=200, content=registry.to_dict())


def build_witness_services(registry):
    services = []
    for witness_id, entry in (registry.registry_data or {}).items():
        endpoint = (entry or {}).get("serviceEndpoint")
        if not endpoint:
            continue

        service_entry = {
            "id": witness_id,
            "type": "WitnessInvitation",
            "serviceEndpoint": endpoint,
        }
        if entry.get("location"):
            service_entry["location"] = entry["location"]
        services.append(service_entry)
    return services


@api_router.get("/.well-known/did.json", tags=["Witness"])
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


api_router.include_router(tails.router, prefix="/tails", tags=["Tails"])
api_router.include_router(explorer.router, prefix="/explorer", include_in_schema=False)
api_router.include_router(admin.router, prefix="/admin")
api_router.include_router(credentials.router)
api_router.include_router(resources.router)
api_router.include_router(identifiers.router)

app.include_router(api_router)
