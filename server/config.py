"""App configuration."""

import logging
import os

from dotenv import load_dotenv
from pydantic_settings import BaseSettings

from typing import Union

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Settings(BaseSettings):
    """App settings."""

    PROJECT_TITLE: str = "DID WebVH Server"
    PROJECT_VERSION: str = "v0"

    API_KEY: str = os.environ.get("API_KEY", "s3cret")
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "s3cret")
    STORAGE_KEY: str = os.environ.get("STORAGE_KEY", "s3cret")
    WEBVH_VERSION: str = os.environ.get("WEBVH_VERSION", "0.5")

    DEFAULT_WITNESS_KEY: Union[str, None] = os.environ.get("DEFAULT_WITNESS_KEY", None)

    DOMAIN: str = os.environ.get("DOMAIN", "localhost")
    DID_WEB_PREFIX: str = "did:web:"
    DID_WEBVH_PREFIX: str = "did:webvh:"
    DID_WEB_BASE: str = f"{DID_WEB_PREFIX}{DOMAIN}"

    # Proof expiration in minutes
    REGISTRATION_PROOF_TTL: int = 60

    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "")
    POSTGRES_SERVER_NAME: str = os.getenv("POSTGRES_SERVER_NAME", "")
    POSTGRES_SERVER_PORT: str = os.getenv("POSTGRES_SERVER_PORT", "")

    ASKAR_DB: str = "sqlite://app.db"
    if POSTGRES_USER and POSTGRES_PASSWORD and POSTGRES_SERVER_NAME and POSTGRES_SERVER_PORT:
        logging.info(f"Using postgres storage: {POSTGRES_SERVER_NAME}:{POSTGRES_SERVER_PORT}")
        ASKAR_DB: str = f"postgres://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER_NAME}:{POSTGRES_SERVER_PORT}/didwebvh-server"
    else:
        logging.info("Using SQLite database")

    SCID_PLACEHOLDER: str = "{SCID}"

    RESERVED_NAMESPACES: list = ["admin", "resources"]


settings = Settings()
