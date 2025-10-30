import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, APIRouter, Request, status
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


api_router.include_router(tails.router, prefix="/tails", tags=["Tails"])
api_router.include_router(explorer.router, prefix="/explorer", include_in_schema=False)
api_router.include_router(admin.router, prefix="/admin")
api_router.include_router(credentials.router)
api_router.include_router(resources.router)
api_router.include_router(identifiers.router)

app.include_router(api_router)
