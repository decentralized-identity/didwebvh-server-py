"""App configuration."""

import logging
import os

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

from fastapi.templating import Jinja2Templates

from typing import Union

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

templates = Jinja2Templates(directory="app/templates")


class Settings(BaseSettings):
    """App settings."""

    PROJECT_TITLE: str = "DID WebVH Server"
    PROJECT_VERSION: str = "v0"

    API_KEY: str = os.environ.get("API_KEY", "webvh")
    DOMAIN: str = os.environ.get("DOMAIN", "localhost")

    SCID_PLACEHOLDER: str = r"{SCID}"
    DID_WEB_PREFIX: str = "did:web:"
    DID_WEBVH_PREFIX: str = "did:webvh:"
    DID_WEB_BASE: str = f"{DID_WEB_PREFIX}{DOMAIN}"

    ATTESTED_RESOURCE_CTX: str = "https://identity.foundation/did-attested-resources/context/v0.1"

    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "")
    POSTGRES_SERVER_NAME: str = os.getenv("POSTGRES_SERVER_NAME", "")
    POSTGRES_SERVER_PORT: str = os.getenv("POSTGRES_SERVER_PORT", "")

    if POSTGRES_USER and POSTGRES_PASSWORD and POSTGRES_SERVER_NAME and POSTGRES_SERVER_PORT:
        logging.info(f"Using postgres storage: {POSTGRES_SERVER_NAME}:{POSTGRES_SERVER_PORT}")
        ASKAR_DB: str = f"postgres://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER_NAME}:{POSTGRES_SERVER_PORT}/didwebvh-server"
    else:
        logging.info("Using SQLite database")
        ASKAR_DB: str = "sqlite://app.db"

    # Recommended for production deployments

    KNOWN_WITNESS_KEY: Union[str, None] = os.environ.get("KNOWN_WITNESS_KEY", None)
    KNOWN_WITNESS_REGISTRY: Union[str, None] = os.environ.get("KNOWN_WITNESS_REGISTRY", None)

    WEBVH_VERSION: str = os.environ.get("WEBVH_VERSION", "1.0")
    WEBVH_WITNESS: bool = eval(os.environ.get("WEBVH_WITNESS", "true").capitalize())
    WEBVH_WATCHER: Union[str, None] = os.environ.get("WEBVH_WATCHER", None)
    WEBVH_PREROTATION: bool = eval(os.environ.get("WEBVH_PREROTATION", "true").capitalize())
    WEBVH_PORTABILITY: bool = eval(os.environ.get("WEBVH_PORTABILITY", "true").capitalize())
    WEBVH_ENDORSEMENT: bool = eval(os.environ.get("WEBVH_ENDORSEMENT", "false").capitalize())

    WEBVH_ICON: str = "https://didwebvh.info/latest/assets/favicon.ico"
    BRANDING: dict = {
        "app_name": "DID WebVH Explorer",
        "app_description": "Visual user inteface to query DID WebVH logs and Attested Resources.",
        "app_icon": os.environ.get("APP_ICON", WEBVH_ICON),
        "app_logo": os.environ.get("APP_LOGO", WEBVH_ICON),
        "app_url": f"https://{DOMAIN}",
    }
    AVATAR_URL: str = "https://api.dicebear.com/9.x/identicon/svg"
    UNIRESOLVER_URL: str = "https://dev.uniresolver.io"

    RESERVED_NAMESPACES: list = ["explorer", "admin", "server", "tails"]


settings = Settings()
