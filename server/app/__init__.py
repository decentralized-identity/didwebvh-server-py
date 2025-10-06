from fastapi import FastAPI, APIRouter, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.routers import policies, identifiers, resources, explorer, tails
import logging
from config import settings

app = FastAPI(title=settings.PROJECT_TITLE, version=settings.PROJECT_VERSION)

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
    return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


@api_router.get("/server/status", tags=["Server"], include_in_schema=False)
async def server_status():
    """Server status endpoint."""
    return JSONResponse(status_code=200, content={"status": "ok", "domain": settings.DOMAIN})


# if settings.ENABLE_TAILS:
api_router.include_router(tails.router, prefix="/tails", tags=["Tails"])

api_router.include_router(explorer.router, prefix="/explorer", include_in_schema=False)
api_router.include_router(policies.router, prefix="/policy")
api_router.include_router(resources.router)
api_router.include_router(identifiers.router)

app.include_router(api_router)
