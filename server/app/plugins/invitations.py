"""Invitation URL utilities."""

import base64
import json
from urllib.parse import urlparse, parse_qs

from config import settings


def decode_invitation_from_url(invitation_url: str) -> dict:
    """Decode an OOB invitation from URL.

    Args:
        invitation_url: URL containing ?oob= parameter with base64-encoded invitation

    Returns:
        Decoded invitation payload as dict

    Raises:
        ValueError: If URL doesn't contain oob parameter or payload is invalid
    """
    parsed = urlparse(invitation_url)
    query = parse_qs(parsed.query)

    if "oob" not in query or not query["oob"]:
        raise ValueError("Invitation URL must include an 'oob' parameter.")

    encoded = query["oob"][0]
    if not encoded:
        raise ValueError("Invitation URL must include an 'oob' parameter.")

    try:
        # Add padding if needed
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding
        decoded = base64.urlsafe_b64decode(encoded)
        return json.loads(decoded.decode("utf-8"))
    except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("Invitation URL contained an invalid payload.") from e


def build_short_invitation_url(witness_id: str, invitation_payload: dict) -> str:
    """Build the server-hosted short URL for a witness invitation.

    Args:
        witness_id: Full did:key identifier for the witness
        invitation_payload: Decoded invitation payload

    Returns:
        Short URL with _oobid parameter
    """
    # Use witness key (multikey part) as _oobid
    witness_key = witness_id.split(":")[-1]
    return f"https://{settings.DOMAIN}/api/invitations?_oobid={witness_key}"
