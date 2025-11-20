"""App configuration."""

import logging
import os
import re
from typing import Union

from dotenv import load_dotenv
from fastapi.templating import Jinja2Templates
from pydantic_settings import BaseSettings

from app.avatar_generator import generate_avatar

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

templates = Jinja2Templates(directory="app/templates")


# Add regex_replace filter to Jinja environment
def regex_replace(s, pattern, replacement):
    """Regex replace filter for Jinja2."""
    return re.sub(pattern, replacement, s)


templates.env.filters["regex_replace"] = regex_replace

# Add generate_avatar as a global function for templates
templates.env.globals["generate_avatar"] = generate_avatar


class Settings(BaseSettings):
    """App settings."""

    PROJECT_TITLE: str = "DID WebVH Server"
    PROJECT_VERSION: str = "v0"

    WEBVH_ADMIN_API_KEY: str = os.environ.get(
        "WEBVH_ADMIN_API_KEY", os.environ.get("WEBVH_API_KEY", os.environ.get("API_KEY", "webvh"))
    )
    DOMAIN: str = os.environ.get("WEBVH_DOMAIN", "localhost")

    SCID_PLACEHOLDER: str = r"{SCID}"
    DID_WEB_PREFIX: str = "did:web:"
    DID_WEBVH_PREFIX: str = "did:webvh:"
    DID_WEB_BASE: str = f"{DID_WEB_PREFIX}{DOMAIN}"

    ATTESTED_RESOURCE_CTX: str = "https://identity.foundation/did-attested-resources/context/v0.1"

    POSTGRES_URL: str = os.getenv("POSTGRES_URL", "")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "")
    POSTGRES_SERVER_NAME: str = os.getenv("POSTGRES_SERVER_NAME", "")
    POSTGRES_SERVER_PORT: str = os.getenv("POSTGRES_SERVER_PORT", "")

    if POSTGRES_URL:
        logging.info(f"Using postgres storage: {POSTGRES_SERVER_NAME}:{POSTGRES_SERVER_PORT}")
        DATABASE_URL: str = POSTGRES_URL

    elif POSTGRES_USER and POSTGRES_PASSWORD and POSTGRES_SERVER_NAME and POSTGRES_SERVER_PORT:
        logging.info(f"Using postgres storage: {POSTGRES_SERVER_NAME}:{POSTGRES_SERVER_PORT}")
        DATABASE_URL: str = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_SERVER_NAME}:{POSTGRES_SERVER_PORT}/didwebvh-server"
    else:
        logging.info("Using SQLite database")
        DATABASE_URL: str = "sqlite:///app.db"

    ENABLE_TAILS: bool = eval(os.environ.get("ENABLE_TAILS", "true").capitalize())

    # Recommended for production deployments

    WEBVH_WITNESS_ID: Union[str, None] = os.environ.get("WEBVH_WITNESS_ID", None)
    WEBVH_WITNESS_INVITATION: Union[str, None] = os.environ.get("WEBVH_WITNESS_INVITATION", None)

    WEBVH_VERSION: str = os.environ.get("WEBVH_VERSION", "1.0")
    WEBVH_WITNESS: bool = eval(os.environ.get("WEBVH_WITNESS", "true").capitalize())
    WEBVH_WATCHER: Union[str, None] = os.environ.get("WEBVH_WATCHER", None)
    WEBVH_PREROTATION: bool = eval(os.environ.get("WEBVH_PREROTATION", "true").capitalize())
    WEBVH_PORTABILITY: bool = eval(os.environ.get("WEBVH_PORTABILITY", "true").capitalize())
    WEBVH_ENDORSEMENT: bool = eval(os.environ.get("WEBVH_ENDORSEMENT", "true").capitalize())

    WEBVH_ICON: str = "https://didwebvh.info/latest/assets/favicon.ico"
    WEBVH_LOGO: str = "https://raw.githubusercontent.com/decentralized-identity/didwebvh-info/main/docs/assets/didwebvh.jpg"
    BRANDING: dict = {
        "app_name": os.environ.get("APP_NAME", "DID WebVH Explorer"),
        "app_description": os.environ.get(
            "APP_DESCRIPTION",
            "Visual user interface to query DID WebVH logs and Attested Resources.",
        ),
        "icon": os.environ.get("APP_ICON", WEBVH_ICON),
        "logo_vertical": os.environ.get("APP_LOGO_VERTICAL", WEBVH_LOGO),
        "logo_horizontal": os.environ.get("APP_LOGO_HORIZONTAL", WEBVH_LOGO),
        "app_url": f"https://{DOMAIN}",
        # Color scheme - Default WebVH Theme
        "primary_color": os.environ.get("APP_PRIMARY_COLOR", "#1a365d"),  # WebVH Deep Blue
        "secondary_color": os.environ.get("APP_SECONDARY_COLOR", "#38a169"),  # WebVH Green
        "accent_color": os.environ.get("APP_ACCENT_COLOR", "#3182ce"),  # WebVH Blue
        # Features
        "show_witness_network": eval(
            os.environ.get("APP_SHOW_WITNESS_NETWORK", "true").capitalize()
        ),
        "show_version_history": eval(
            os.environ.get("APP_SHOW_VERSION_HISTORY", "true").capitalize()
        ),
        "show_resources": eval(os.environ.get("APP_SHOW_RESOURCES", "true").capitalize()),
    }
    UNIRESOLVER_URL: str = "https://dev.uniresolver.io"

    RESERVED_NAMESPACES: list = ["api", ".well-known"]


settings = Settings()
