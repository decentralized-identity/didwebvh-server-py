"""Credential management endpoints."""

import copy
import json
import base64
import logging

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.models.web_schemas import CredentialUpload
from app.plugins.storage import StorageManager as SQLStorage
from app.plugins.askar import AskarVerifier
from app.db.models import DidControllerRecord
from app.dependencies import get_did_controller_dependency

router = APIRouter(tags=["Verifiable Credentials"])
logger = logging.getLogger(__name__)

sql_storage = SQLStorage()
verifier = AskarVerifier()


def _detect_credential_format(credential: dict) -> str:
    """Detect credential format from type field."""
    cred_type = credential.get("type")
    types_list = cred_type if isinstance(cred_type, list) else [cred_type] if cred_type else []

    if "EnvelopedVerifiableCredential" in types_list:
        return "EnvelopedVerifiableCredential"
    elif "VerifiableCredential" in types_list:
        return "VerifiableCredential"
    return "Unknown"


def _validate_enveloped_vc_data_url(credential_id: str):
    """Validate EnvelopedVC has proper data URL format."""
    if not credential_id.startswith("data:application/vc+jwt,"):
        if credential_id.startswith("data:"):
            media_type = (
                credential_id.split(",")[0].replace("data:", "")
                if "," in credential_id
                else "unknown"
            )
            raise HTTPException(
                status_code=400,
                detail=(
                    f"EnvelopedVerifiableCredential must use 'application/vc+jwt' "
                    f"media type. Found: '{media_type}'."
                ),
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=(
                    "EnvelopedVerifiableCredential must use a data URL with "
                    "'application/vc+jwt' media type"
                ),
            )


def _verify_enveloped_credential(credential: dict, did_controller, verifier) -> str:
    """Verify EnvelopedVerifiableCredential JWT signature.

    Returns:
        str: The verification method ID used

    Raises:
        HTTPException: If verification fails
    """
    credential_id = credential.get("id", "")
    jwt_token = credential_id.split(",", 1)[1]

    # Verify signature (raises HTTPException if invalid)
    _ = verifier.verify_jwt_signature(jwt_token, did_controller.document, did_controller.did)

    # Extract verification method from JWT header
    header_b64 = jwt_token.split(".")[0]
    header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
    header = json.loads(base64.urlsafe_b64decode(header_b64_padded))
    verification_method_id = header.get("kid")

    logger.info(f"✓ EnvelopedVC JWT verified: {verification_method_id}")
    return verification_method_id


def _verify_regular_credential(credential: dict, did_controller, verifier) -> str:
    """Verify regular VerifiableCredential with DataIntegrityProof.

    Returns:
        str: The verification method ID used

    Raises:
        HTTPException: If verification fails or no valid proof found
    """
    credential_copy = copy.deepcopy(credential)
    proofs = credential_copy.pop("proof", None)

    if not proofs:
        raise HTTPException(
            status_code=400, detail="VerifiableCredential must have a 'proof' field"
        )

    # Handle both single proof and proof sets
    proofs = proofs if isinstance(proofs, list) else [proofs]

    # Find the proof from the issuer (did:webvh:)
    issuer_proof = next(
        (p for p in proofs if p.get("verificationMethod", "").startswith("did:webvh:")),
        None,
    )

    if not issuer_proof:
        raise HTTPException(
            status_code=400, detail="VerifiableCredential must have a proof from a did:webvh issuer"
        )

    # Verify issuer matches the DID controller
    issuer = credential.get("issuer", {})
    issuer_did = issuer.get("id") if isinstance(issuer, dict) else issuer

    if not issuer_did or issuer_did != did_controller.did:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Credential issuer ({issuer_did}) must match DID controller ({did_controller.did})"
            ),
        )

    # Verify the proof (raises HTTPException if invalid)
    verifier.verify_proof(credential_copy, issuer_proof)
    verification_method_id = issuer_proof.get("verificationMethod")
    logger.info(f"✓ VC proof verified: {verification_method_id}")
    return verification_method_id


def _extract_storage_credential_id(credential: dict, credential_format: str, options) -> str:
    """Extract simple credential ID for storage/retrieval.

    Priority:
      1. options.credentialId (recommended - explicit control)
      2. Extract from credential.id (fallback)
    """
    # Check for explicit credentialId in options
    if options and hasattr(options, "credentialId") and options.credentialId:
        logger.info(f"Using credentialId from options: {options.credentialId}")
        return options.credentialId

    # Fallback: extract from credential.id
    full_id = credential.get("id", "")
    if not full_id:
        raise HTTPException(
            status_code=400,
            detail="Credential must have an 'id' field or provide options.credentialId",
        )

    # For EnvelopedVCs with data URLs, keep as-is
    if credential_format == "EnvelopedVerifiableCredential":
        storage_id = full_id
    else:
        # For regular VCs: extract last segment from URL
        storage_id = full_id.split("/")[-1] if "/" in full_id else full_id

    logger.info(f"Extracted credentialId: {storage_id}")
    return storage_id


@router.post("/{namespace}/{identifier}/credentials")
async def publish_credential(
    request_body: CredentialUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """Publish a verifiable credential."""
    logger.info(
        f"=== Publishing credential for {did_controller.namespace}/{did_controller.alias} ==="
    )

    verifiable_credential = vars(request_body)["verifiableCredential"].model_dump()
    options = vars(request_body).get("options")

    # 1. Detect and validate credential format
    credential_format = _detect_credential_format(verifiable_credential)
    if credential_format == "Unknown":
        raise HTTPException(
            status_code=400,
            detail=(
                "Credential type must be 'VerifiableCredential' or 'EnvelopedVerifiableCredential'"
            ),
        )
    logger.info(f"Credential format: {credential_format}")

    # 2. Validate EnvelopedVC data URL format (if applicable)
    if credential_format == "EnvelopedVerifiableCredential":
        _validate_enveloped_vc_data_url(verifiable_credential.get("id", ""))

    # 3. Verify credential cryptographically (blocking - must pass to store)
    if credential_format == "EnvelopedVerifiableCredential":
        verification_method_id = _verify_enveloped_credential(
            verifiable_credential, did_controller, verifier
        )
    else:  # VerifiableCredential
        verification_method_id = _verify_regular_credential(
            verifiable_credential, did_controller, verifier
        )

    # 4. Extract storage credential ID
    storage_credential_id = _extract_storage_credential_id(
        verifiable_credential, credential_format, options
    )

    # 5. Store verified credential in SQL database
    try:
        sql_storage.create_credential(
            did_controller.scid,
            verifiable_credential,
            custom_id=storage_credential_id,
            verified=True,  # Only verified credentials are stored
            verification_method=verification_method_id,
        )
        logger.info(f"Credential {storage_credential_id} stored successfully")
    except IntegrityError:
        # Duplicate credential ID (UNIQUE constraint violation)
        logger.warning(f"Credential {storage_credential_id} already exists")
        raise HTTPException(
            status_code=409,
            detail=(
                f"Credential with ID '{storage_credential_id}' already exists. "
                f"Use PUT to update or choose a different credentialId."
            ),
        )
    except Exception as e:
        logger.error(f"Failed to store credential: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to store credential: {str(e)}")

    return JSONResponse(status_code=201, content=verifiable_credential)


@router.put("/{namespace}/{identifier}/credentials/{credential_id}")
async def update_credential(
    credential_id: str,
    request_body: CredentialUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
):
    """Update an existing credential (must be cryptographically verified)."""
    logger.info(f"=== Updating credential {credential_id} ===")

    # 1. Get existing credential from SQL database
    existing_credential = sql_storage.get_credential(credential_id)
    if not existing_credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # 2. Verify the credential belongs to this DID controller
    if existing_credential.scid != did_controller.scid:
        raise HTTPException(status_code=404, detail="Credential not found")

    # 3. Extract and validate new credential
    verifiable_credential = vars(request_body)["verifiableCredential"].model_dump()

    # 4. Detect and validate credential format
    credential_format = _detect_credential_format(verifiable_credential)
    if credential_format == "Unknown":
        raise HTTPException(
            status_code=400,
            detail=(
                "Credential type must be 'VerifiableCredential' or 'EnvelopedVerifiableCredential'"
            ),
        )

    # 5. Validate EnvelopedVC data URL format (if applicable)
    if credential_format == "EnvelopedVerifiableCredential":
        _validate_enveloped_vc_data_url(verifiable_credential.get("id", ""))

    # 6. Verify credential cryptographically (blocking - must pass to update)
    if credential_format == "EnvelopedVerifiableCredential":
        verification_method_id = _verify_enveloped_credential(
            verifiable_credential, did_controller, verifier
        )
    else:  # VerifiableCredential
        verification_method_id = _verify_regular_credential(
            verifiable_credential, did_controller, verifier
        )

    # 7. Update credential in SQL database
    try:
        updated_credential = sql_storage.update_credential(
            credential_id, verifiable_credential, verification_method_id
        )
        if not updated_credential:
            raise HTTPException(status_code=404, detail="Credential not found for update")

        logger.info(f"Credential {credential_id} updated successfully")
        return JSONResponse(status_code=200, content=updated_credential.verifiable_credential)
    except ValueError as e:
        logger.error(f"Invalid credential data: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update credential: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update credential: {str(e)}")


@router.get("/{namespace}/{identifier}/credentials/{credential_id}")
async def get_credential(
    credential_id: str, did_controller: DidControllerRecord = Depends(get_did_controller_dependency)
):
    """Fetch an existing credential."""
    logger.info(f"=== Fetching credential {credential_id} ===")

    # Get credential from SQL database
    credential_record = sql_storage.get_credential(credential_id)
    if not credential_record:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Verify the credential belongs to this DID controller
    if credential_record.scid != did_controller.scid:
        raise HTTPException(status_code=403, detail="Credential does not belong to this DID")

    return JSONResponse(status_code=200, content=credential_record.verifiable_credential)
