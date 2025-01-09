from fastapi import FastAPI, APIRouter
from fastapi.responses import JSONResponse
from app.routers import identifiers, resolvers
from config import settings

app = FastAPI(title=settings.PROJECT_TITLE, version=settings.PROJECT_VERSION)

api_router = APIRouter()


@api_router.get("/server/status", tags=["Server"], include_in_schema=False)
async def server_status():
    return JSONResponse(status_code=200, content={"status": "ok"})


api_router.include_router(identifiers.router)
api_router.include_router(resolvers.router)

app.include_router(api_router)
