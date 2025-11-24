"""Utility functions for the DID Web server."""

import base64
import jcs
import json
import logging
from datetime import datetime, timezone, timedelta
from operator import itemgetter
from typing import Optional

from fastapi import HTTPException, status
from multiformats import multibase, multihash

from app.plugins.invitations import (
    build_short_invitation_url,
    decode_invitation_from_url,
)
from config import settings

logger = logging.getLogger(__name__)

MULTIKEY_PARAMS = {"ed25519": {"length": 48, "prefix": "z6M"}}


def multipart_reader(request_body, boundary):
    """Read multipart header."""
    file_content = None
    parts = request_body.split(b"--" + boundary)
    for part in parts:
        header_split = part.split(b"\r\n\r\n", 1)
        if len(header_split) == 2:
            file_content = header_split[1].rstrip(b"\r\n--")
            break
    return file_content


def did_to_https(did):
    """DID to https transformation."""
    domain, namespace, identifier = itemgetter(3, 4, 5)(did.split(":"))
    return f"https://{domain}/{namespace}/{identifier}"


def beautify_date(value):
    """Returns a human readable date from a ISO datetime string or datetime object."""
    if not value:
        return ""

    # If it's already a datetime object, format it directly
    if isinstance(value, datetime):
        return value.strftime("%B %d, %Y")

    # If it's a string, parse it first
    if isinstance(value, str):
        date_str = value.split("T")[0]
        date_obj = datetime.strptime(date_str, "%Y-%m-%d")
        return date_obj.strftime("%B %d, %Y")

    # Fallback: try to convert to string
    try:
        return str(value)
    except Exception:
        return ""


def resource_id_to_url(resource_id):
    """Returns a resource url from it's id."""
    author_id = resource_id.split("/")[0]
    domain, namespace, identifier = itemgetter(3, 4, 5)(author_id.split(":"))
    path = "/".join(resource_id.split("/")[1:])
    return f"https://{domain}/{namespace}/{identifier}/{path}"


def resource_details(resource):
    """Returns resource specific details."""
    resource_type = resource.get("metadata").get("resourceType")
    if resource_type == "anonCredsSchema":
        return {
            "name": resource.get("content").get("name"),
            "version": resource.get("content").get("version"),
        }
    elif resource_type == "anonCredsCredDef":
        return {"tag": resource.get("content").get("tag")}
    elif resource_type == "anonCredsRevocRegDef":
        return {
            "tag": resource.get("content").get("tag"),
            "size": resource.get("content").get("value").get("maxCredNum"),
        }
    elif resource_type == "anonCredsStatusList":
        return {
            "size": len(resource.get("content").get("revocationList")),
            "timestamp": resource.get("content").get("timestamp"),
        }
    return {}


def get_client_id(namespace, identifier):
    """Create the client id."""
    return f"{namespace}:{identifier}"


def is_valid_multikey(multikey, alg="ed25519"):
    """Test for multikey string."""
    if not multikey.startswith(MULTIKEY_PARAMS[alg]["prefix"]) or len(multikey) != 48:
        return False
    if len(multikey) != MULTIKEY_PARAMS[alg]["length"]:
        return False
    return True


def is_webvh_did(did):
    """Test for WebVH string."""
    try:
        assert did.split(":")[0] == "did"
        assert did.split(":")[1] == "webvh"
        assert did.split(":")[3]  # SCID
        assert did.split(":")[4] == settings.DOMAIN
        assert did.split(":")[5]  # namespace
        assert did.split(":")[6]  # identifier
        return True
    except AssertionError:
        return False


def digest_multibase(content):
    """Calculate digest multibase."""
    digest_multihash = multihash.digest(jcs.canonicalize(content), "sha2-256")
    digest_multibase = multibase.encode(digest_multihash, "base58btc")
    return digest_multibase


def to_did_web(namespace: str, identifier: str):
    """Convert namespace and identifier to a DID Web identifier."""
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


def derive_did(namespace, identifier):
    """Derive a DID from a namespace and identifier."""
    return f"{settings.DID_WEB_BASE}:{namespace}:{identifier}"


def find_key(did_doc, kid):
    """Find a key in a DID document."""
    return next(
        (vm["publicKeyMultibase"] for vm in did_doc["verificationMethod"] if vm["id"] == kid),
        None,
    )


def find_proof(proof_set, kid):
    """Find a proof in a proof set."""
    return next(
        (proof for proof in proof_set if proof["verificationMethod"] == kid),
        None,
    )


def find_verification_method(did_doc, kid):
    """Find a verification method's public key given a key id."""
    return next(
        (vm["publicKeyMultibase"] for vm in did_doc["verificationMethod"] if vm["id"] == kid),
        None,
    )


def first_proof(proof):
    """Return the first proof from a proof set."""
    return proof if isinstance(proof, dict) else proof[0]


def timestamp(minutes_delta=None):
    """Create timestamps."""
    dt = (
        datetime.now(timezone.utc) + timedelta(minutes=minutes_delta)
        if minutes_delta
        else datetime.now(timezone.utc)
    )
    return str(dt.isoformat("T", "seconds")).replace("+00:00", "Z")


def webvh_to_web_doc(did_document, scid):
    """Trasform did webvh doc to did web."""
    return json.loads(json.dumps(did_document).replace(f"did:webvh:{scid}:", "did:web:"))


def decode_enveloped_credential(verifiable_credential: dict) -> tuple[list, dict]:
    """Decode an EnvelopedVerifiableCredential to extract types and subject.

    For EnvelopedVerifiableCredentials, decodes the JWT payload to get the actual
    credential information. For regular credentials, returns data directly.

    Args:
        verifiable_credential: The credential dict (either enveloped or regular)

    Returns:
        Tuple of (credential_types, credential_subject)
        - credential_types: List of credential type strings
        - credential_subject: The credentialSubject dict
    """
    # Get credential types
    cred_types = verifiable_credential.get("type", [])
    if isinstance(cred_types, str):
        cred_types = [cred_types]

    # Check if this is an EnvelopedVerifiableCredential
    if "EnvelopedVerifiableCredential" in cred_types:
        try:
            # Extract JWT from data URL
            data_url = verifiable_credential.get("id", "")
            if data_url.startswith("data:") and "," in data_url:
                jwt_token = data_url.split(",", 1)[1]
                parts = jwt_token.split(".")

                if len(parts) == 3:
                    # Decode JWT payload (the actual credential)
                    payload = parts[1]
                    payload += "=" * (4 - len(payload) % 4)  # Add padding
                    decoded_vc = json.loads(base64.urlsafe_b64decode(payload))

                    # Extract types from decoded credential
                    decoded_types = decoded_vc.get("type", [])
                    if isinstance(decoded_types, str):
                        decoded_types = [decoded_types]
                    cred_types = decoded_types

                    # Extract subject from decoded credential
                    subject = decoded_vc.get("credentialSubject", {})
                    if isinstance(subject, list):
                        subject = subject[0] if subject else {}

                    return cred_types, subject
        except Exception:
            # If decoding fails, fall through to default handling
            pass

    # Regular credential or fallback - extract subject directly
    subject = verifiable_credential.get("credentialSubject", {})
    if isinstance(subject, list):
        subject = subject[0] if subject else {}

    return cred_types, subject


def _validate_enveloped_credential_data_url(data_url: str) -> None:
    """Validate data URL format and media type for EnvelopedVerifiableCredential."""
    if not data_url.startswith("data:"):
        raise ValueError("EnvelopedVerifiableCredential must use a data URL for the 'id' field")

    if not data_url.startswith("data:application/vc+jwt,"):
        media_type = data_url.split(",")[0].replace("data:", "") if "," in data_url else "unknown"
        raise ValueError(
            f"EnvelopedVerifiableCredential must use "
            f"'application/vc+jwt' media type. "
            f"Found: '{media_type}'. Only VC-JOSE format is supported."
        )

    if "," not in data_url:
        raise ValueError("Invalid data URL format - missing comma separator")


def _decode_jwt_payload(data_url: str) -> dict:
    """Decode JWT payload from data URL."""
    jwt_token = data_url.split(",", 1)[1]
    parts = jwt_token.split(".")

    if len(parts) != 3:
        raise ValueError(
            "Invalid JWT format in EnvelopedVerifiableCredential - "
            "must have 3 parts (header.payload.signature)"
        )

    payload = parts[1]
    payload += "=" * (4 - len(payload) % 4)  # Add padding
    return json.loads(base64.urlsafe_b64decode(payload))


def _validate_decoded_credential(decoded_vc: dict, custom_id: str | None) -> None:
    """Validate decoded credential has required fields."""
    if "@context" not in decoded_vc:
        raise ValueError("JWT payload in EnvelopedVerifiableCredential must have '@context' field")

    if "id" not in decoded_vc and not custom_id:
        raise ValueError("JWT payload in EnvelopedVerifiableCredential must have 'id' field")

    if "type" not in decoded_vc:
        raise ValueError("JWT payload in EnvelopedVerifiableCredential must have 'type' field")

    payload_types = decoded_vc.get("type", [])
    if isinstance(payload_types, str):
        payload_types = [payload_types]
    if "VerifiableCredential" not in payload_types:
        raise ValueError("JWT payload 'type' must include 'VerifiableCredential'")

    if "issuer" not in decoded_vc:
        raise ValueError("JWT payload in EnvelopedVerifiableCredential must have 'issuer' field")

    if "credentialSubject" not in decoded_vc:
        raise ValueError(
            "JWT payload in EnvelopedVerifiableCredential must have 'credentialSubject' field"
        )


def _extract_metadata_from_credential(credential: dict, custom_id: str | None) -> dict:
    """Extract metadata from a credential dict (enveloped or regular)."""
    credential_id = custom_id if custom_id else credential.get("id")
    if not credential_id:
        raise ValueError("Credential must have an 'id' field or custom_id must be provided")

    issuer = credential.get("issuer", {})
    issuer_did = issuer.get("id") if isinstance(issuer, dict) else issuer

    credential_type = credential.get("type", [])
    if not isinstance(credential_type, list):
        credential_type = [credential_type]

    credential_subject = credential.get("credentialSubject", {})
    if isinstance(credential_subject, list):
        credential_subject = credential_subject[0] if credential_subject else {}
    subject_id = credential_subject.get("id") if isinstance(credential_subject, dict) else None

    valid_from_str = credential.get("validFrom")
    valid_until_str = credential.get("validUntil")
    valid_from = parse_datetime(valid_from_str) if valid_from_str else None
    valid_until = parse_datetime(valid_until_str) if valid_until_str else None

    return {
        "credential_id": credential_id,
        "issuer_did": issuer_did,
        "credential_type": credential_type,
        "subject_id": subject_id,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def extract_credential_metadata(verifiable_credential: dict, custom_id: str | None = None) -> dict:
    """Extract metadata from a verifiable credential (enveloped or regular).

    For EnvelopedVerifiableCredentials, decodes and validates the JWT payload.
    For regular credentials, extracts metadata directly.

    Args:
        verifiable_credential: The credential dict (either enveloped or regular)
        custom_id: Optional custom credential ID (overrides verifiable_credential.id)

    Returns:
        Dictionary with extracted metadata:
        - credential_id: The credential ID
        - issuer_did: The issuer DID
        - credential_type: List of credential types
        - subject_id: The subject ID (if present)
        - valid_from: Valid from datetime (if present)
        - valid_until: Valid until datetime (if present)

    Raises:
        ValueError: If credential validation fails
    """
    vc_types = verifiable_credential.get("type", [])
    if isinstance(vc_types, str):
        vc_types = [vc_types]

    is_enveloped = "EnvelopedVerifiableCredential" in vc_types

    if is_enveloped:
        data_url = verifiable_credential.get("id", "")
        _validate_enveloped_credential_data_url(data_url)
        decoded_vc = _decode_jwt_payload(data_url)
        _validate_decoded_credential(decoded_vc, custom_id)
        # Use data_url as fallback for credential_id if needed
        if not custom_id and "id" not in decoded_vc:
            decoded_vc["id"] = data_url
        return _extract_metadata_from_credential(decoded_vc, custom_id)

    return _extract_metadata_from_credential(verifiable_credential, custom_id)


def create_pagination(page: int, limit: int, total: int, total_pages: int) -> dict:
    """Create pagination metadata dict for explorer UI.

    Args:
        page: Current page number (1-indexed)
        limit: Items per page
        total: Total number of items
        total_pages: Total number of pages

    Returns:
        Dictionary with pagination metadata including navigation flags
    """
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "total_pages": total_pages,
        "has_prev": page > 1,
        "has_next": page < total_pages,
        "prev_page": page - 1 if page > 1 else None,
        "next_page": page + 1 if page < total_pages else None,
    }


def build_witness_services(registry):
    """Build witness services list from registry for DID document.

    Args:
        registry: KnownWitnessRegistry object with registry_data

    Returns:
        List of service entries for the DID document
    """
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
        if entry.get("name"):
            service_entry["name"] = entry["name"]
        if entry.get("location"):
            service_entry["location"] = entry["location"]
        services.append(service_entry)
    return services


def validate_witness_id(witness_did: str) -> str:
    """Validate witness DID and return multikey.

    Args:
        witness_did: Full did:key identifier for the witness

    Returns:
        The multikey portion of the witness DID

    Raises:
        HTTPException: If the witness DID is invalid
    """
    if not witness_did.startswith("did:key:"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Witness id must be a did:key identifier.",
        )
    multikey = witness_did.split("did:key:")[-1]
    if not is_valid_multikey(multikey, alg="ed25519"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid witness id, must be ed25519 multikey.",
        )
    return multikey


def validate_invitation_goal(invitation_payload: dict, witness_did: str) -> None:
    """Validate that invitation goal_code and goal match witness requirements.

    Args:
        invitation_payload: Decoded invitation payload dict
        witness_did: Full did:key identifier for the witness

    Raises:
        HTTPException: If invitation goal_code or goal don't match requirements
    """
    goal_code = invitation_payload.get("goal_code")
    goal = invitation_payload.get("goal")

    if goal_code != "witness-service":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid invitation goal_code. Expected 'witness-service', got '{goal_code}'",
        )

    if goal != witness_did:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invitation goal does not match witness ID. Expected '{witness_did}', got '{goal}'"
            ),
        )


def process_invitation(
    invitation_url: str, witness_did: str, provided_label: str | None
) -> tuple[dict, str, str]:
    """Process invitation URL and return payload, label, and short endpoint.

    Label priority: provided_label > invitation label > fallback

    Args:
        invitation_url: Full invitation URL with ?oob= parameter
        witness_did: Full did:key identifier for the witness
        provided_label: Optional label provided by admin (takes priority)

    Returns:
        Tuple of (invitation_payload, label, short_service_endpoint)

    Raises:
        HTTPException: If invitation validation fails
    """
    invitation_payload = decode_invitation_from_url(invitation_url)
    validate_invitation_goal(invitation_payload, witness_did)

    # Use provided label if available, otherwise use invitation label, otherwise fallback
    invitation_label = provided_label or invitation_payload.get("label") or "Witness Service"

    short_service_endpoint = build_short_invitation_url(witness_did, invitation_payload)
    return invitation_payload, invitation_label, short_service_endpoint


def create_witness_entry(
    invitation_label: str, short_service_endpoint: str | None, invitation_url: str
) -> dict:
    """Create witness registry entry.

    Args:
        invitation_label: Label for the witness service
        short_service_endpoint: Short URL endpoint (preferred)
        invitation_url: Full invitation URL (fallback)

    Returns:
        Dictionary with witness entry data
    """
    entry = {"name": invitation_label}
    if short_service_endpoint:
        entry["serviceEndpoint"] = short_service_endpoint
    elif invitation_url:
        entry["serviceEndpoint"] = invitation_url
    return entry


def parse_datetime(date_string: str) -> Optional[datetime]:
    """Parse ISO 8601 datetime string to Python datetime object.

    Args:
        date_string: ISO 8601 formatted date string

    Returns:
        datetime object or None if parsing fails
    """
    if not date_string:
        return None

    try:
        # Try ISO format with timezone
        return datetime.fromisoformat(date_string.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        try:
            # Try without timezone
            return datetime.fromisoformat(date_string)
        except (ValueError, AttributeError):
            logger.warning(f"Failed to parse datetime: {date_string}")
            return None
