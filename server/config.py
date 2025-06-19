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

    API_KEY: str = os.environ.get("API_KEY", "webvh")
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "s3cret")
    STORAGE_KEY: str = os.environ.get("STORAGE_KEY", "s3cret")

    DOMAIN: str = os.environ.get("DOMAIN", "localhost")
    SCID_PLACEHOLDER: str = r'{SCID}'
    DID_WEB_PREFIX: str = "did:web:"
    DID_WEBVH_PREFIX: str = "did:webvh:"
    DID_WEB_BASE: str = f"{DID_WEB_PREFIX}{DOMAIN}"

    DEFAULT_WITNESS_KEY: Union[str, None] = os.environ.get("DEFAULT_WITNESS_KEY", None)

    # Proof expiration in minutes
    REGISTRATION_PROOF_TTL: int = 60

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
    ENABLE_POLICY_MODULE: bool = os.getenv("ENABLE_POLICY_MODULE", True)
    
    
    KNOWN_WITNESS_KEY: Union[str, None] = os.environ.get("KNOWN_WITNESS_KEY", None)
    KNOWN_WITNESS_REGISTRY: Union[str, None] = os.environ.get("KNOWN_WITNESS_REGISTRY", None)
    WEBVH_ENDORSEMENT: bool = os.environ.get("WEBVH_ENDORSEMENT", True)
    WEBVH_VERSION: str = os.environ.get("WEBVH_VERSION", '1.0')
    WEBVH_WITNESS: bool = os.environ.get("WEBVH_WITNESS", True)
    WEBVH_WATCHER: Union[str, None] = os.environ.get("WEBVH_WATCHER", None)
    WEBVH_PREROTATION: bool = os.environ.get("WEBVH_PREROTATION", True)
    WEBVH_PORTABILITY: bool = os.environ.get("WEBVH_PORTABILITY", True)
    WEBVH_VALIDITY: int = os.environ.get("WEBVH_VALIDITY", 0)


settings = Settings()
