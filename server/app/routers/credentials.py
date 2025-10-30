"""Credential management endpoints."""

import copy
import json
import base64
import logging

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from aries_askar import Key
from aries_askar.bindings import LocalKeyHandle
from multiformats import multibase
from hashlib import sha256

from app.models.web_schemas import CredentialUpload
from app.plugins.storage import StorageManager as SQLStorage
from app.plugins.askar import AskarVerifier
from app.db.models import DidControllerRecord

router = APIRouter(tags=["Verifiable Credentials"])
logger = logging.getLogger(__name__)

sql_storage = SQLStorage()
verifier = AskarVerifier()


# Dependency to get DID controller from path parameters
async def get_did_controller_dependency(
    namespace: str,
    identifier: str
) -> DidControllerRecord:
    """Get DID controller from database, raise 404 if not found."""
    did_controller = sql_storage.get_did_controller_by_alias(namespace, identifier)
    if not did_controller:
        raise HTTPException(status_code=404, detail="DID not found. Create the DID first.")
    return did_controller


@router.post("/{namespace}/{identifier}/credentials")
async def publish_credential(
    request_body: CredentialUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency)
):
    """Publish a verifiable credential."""
    logger.info(f"=== Publishing credential for {did_controller.namespace}/{did_controller.alias} ===")
    
    verifiable_credential = vars(request_body)["verifiableCredential"].model_dump()
    logger.debug(f"Credential ID: {verifiable_credential.get('id', 'unknown')}")
    
    # Check credential type/format
    credential_type = verifiable_credential.get("type")
    if isinstance(credential_type, list):
        if "EnvelopedVerifiableCredential" in credential_type:
            credential_format = "EnvelopedVerifiableCredential"
        elif "VerifiableCredential" in credential_type:
            credential_format = "VerifiableCredential"
        else:
            credential_format = "Unknown"
    else:
        credential_format = credential_type if credential_type else "Unknown"
    
    logger.info(f"Credential format: {credential_format}")
    
    # Validate format is recognized
    if credential_format == "Unknown":
        logger.error(f"Unrecognized credential type: {credential_type}")
        raise HTTPException(
            status_code=400, 
            detail="Credential type must be 'VerifiableCredential' or 'EnvelopedVerifiableCredential'"
        )
    
    # Validate and verify EnvelopedVerifiableCredential (VC-JOSE)
    if credential_format == "EnvelopedVerifiableCredential":
        credential_id = verifiable_credential.get("id", "")
        if not credential_id.startswith("data:application/vc+jwt,"):
            # Extract actual media type for error message
            if credential_id.startswith("data:"):
                media_type = credential_id.split(",")[0].replace("data:", "") if "," in credential_id else "unknown"
                logger.error(f"Invalid media type for EnvelopedVC: {media_type}")
                raise HTTPException(
                    status_code=400,
                    detail=f"EnvelopedVerifiableCredential must use 'application/vc+jwt' media type (VC-JOSE). Found: '{media_type}'. Other formats are not supported."
                )
            else:
                logger.error(f"EnvelopedVC missing data URL: {credential_id}")
                raise HTTPException(
                    status_code=400,
                    detail="EnvelopedVerifiableCredential must use a data URL with 'application/vc+jwt' media type"
                )
        
        # Verify JWT signature
        try:
            jwt_token = credential_id.split(",", 1)[1]
            parts = jwt_token.split(".")
            
            if len(parts) != 3:
                raise HTTPException(status_code=400, detail="Invalid JWT format - must have 3 parts")
            
            # Decode header and payload
            header_b64, payload_b64, signature_b64 = parts
            
            # Add padding for base64 decoding
            header_b64_padded = header_b64 + '=' * (4 - len(header_b64) % 4)
            payload_b64_padded = payload_b64 + '=' * (4 - len(payload_b64) % 4)
            signature_b64_padded = signature_b64 + '=' * (4 - len(signature_b64) % 4)
            
            header = json.loads(base64.urlsafe_b64decode(header_b64_padded))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64_padded))
            signature_bytes = base64.urlsafe_b64decode(signature_b64_padded)
            
            # Get verification method from JWT header (kid)
            verification_method_id = header.get("kid")
            if not verification_method_id:
                raise HTTPException(status_code=400, detail="JWT header missing 'kid' field")
            
            # Extract issuer DID from payload
            issuer = payload.get("issuer", {})
            issuer_did = issuer.get("id") if isinstance(issuer, dict) else issuer
            
            if not issuer_did:
                raise HTTPException(status_code=400, detail="Credential payload missing issuer")
            
            # Verify the issuer DID matches the DID controller (credentials must be self-issued)
            if not issuer_did.startswith(f"did:webvh:") or issuer_did != did_controller.did:
                raise HTTPException(
                    status_code=403, 
                    detail=f"Credential issuer ({issuer_did}) must match the DID controller ({did_controller.did})"
                )
            
            # Get the public key from the DID document
            controller_document = did_controller.document
            verification_method = next(
                (vm for vm in controller_document.get("verificationMethod", []) 
                 if vm["id"] == verification_method_id),
                None
            )
            
            if not verification_method:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Verification method '{verification_method_id}' not found in DID document"
                )
            
            # Extract public key (multikey format)
            multikey = verification_method.get("publicKeyMultibase")
            if not multikey:
                raise HTTPException(status_code=400, detail="Verification method missing publicKeyMultibase")
            
            # Create Askar key from public key
            public_key_bytes = bytes(bytearray(multibase.decode(multikey))[2:])  # Skip multicodec prefix
            key = Key(LocalKeyHandle()).from_public_bytes(alg="ed25519", public=public_key_bytes)
            
            # Verify JWT signature (EdDSA signs the header.payload)
            message = f"{header_b64}.{payload_b64}".encode()
            
            if not key.verify_signature(message=message, signature=signature_bytes):
                raise HTTPException(status_code=400, detail="JWT signature verification failed")
            
            logger.info(f"✓ EnvelopedVC JWT signature verified for {issuer_did}")
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"JWT verification failed: {e}")
            raise HTTPException(status_code=400, detail=f"JWT verification failed: {str(e)}")
    
    # Verify regular VerifiableCredential with DataIntegrityProof
    elif credential_format == "VerifiableCredential":
        # Extract and validate proof
        credential_copy = copy.deepcopy(verifiable_credential)
        proofs = credential_copy.pop("proof", None)
        
        if not proofs:
            raise HTTPException(status_code=400, detail="VerifiableCredential must have a 'proof' field")
        
        # Handle both single proof and proof sets
        proofs = proofs if isinstance(proofs, list) else [proofs]
        
        # Find the proof from the issuer (did:webvh:)
        issuer_proof = next(
            (proof for proof in proofs if proof.get("verificationMethod", "").startswith("did:webvh:")),
            None
        )
        
        if not issuer_proof:
            raise HTTPException(
                status_code=400, 
                detail="VerifiableCredential must have a proof from a did:webvh issuer"
            )
        
        # Verify issuer matches the DID controller
        issuer = verifiable_credential.get("issuer", {})
        issuer_did = issuer.get("id") if isinstance(issuer, dict) else issuer
        
        if not issuer_did or issuer_did != did_controller.did:
            raise HTTPException(
                status_code=403,
                detail=f"Credential issuer ({issuer_did}) must match the DID controller ({did_controller.did})"
            )
        
        # Verify the proof using AskarVerifier
        try:
            controller_document = did_controller.document
            verifier.verify_proof(credential_copy, issuer_proof)
            logger.info(f"✓ VerifiableCredential proof verified for {issuer_did}")
        except HTTPException as e:
            logger.error(f"Proof verification failed: {e.detail}")
            raise
        except Exception as e:
            logger.error(f"Proof verification failed: {e}")
            raise HTTPException(status_code=400, detail=f"Proof verification failed: {str(e)}")

    # Check for credentialId in options
    # For EnvelopedVCs, we need to preserve the data URL and use options.credentialId as the lookup key
    options = vars(request_body).get("options")
    custom_credential_id = None
    if options and hasattr(options, "credentialId") and options.credentialId:
        logger.info(f"Using custom credentialId from options: {options.credentialId}")
        custom_credential_id = options.credentialId
        
        # Only override ID for non-enveloped credentials
        if credential_format != "EnvelopedVerifiableCredential":
            verifiable_credential["id"] = custom_credential_id
    
    # Ensure credential has an ID
    if not verifiable_credential.get("id"):
        logger.error("Credential missing ID field")
        raise HTTPException(status_code=400, detail="Credential must have an 'id' field")

    # Store credential in SQL database (uses scid from FK relationship)
    # Mark as format-verified (we validated the format above)
    try:
        sql_storage.create_credential(
            did_controller.scid, 
            verifiable_credential, 
            custom_id=custom_credential_id,
            verified=True,  # Format validation passed
            verification_method="format-validation"
        )
        stored_id = custom_credential_id if custom_credential_id else verifiable_credential['id']
        logger.info(f"Credential {stored_id} stored successfully")
    except IntegrityError as e:
        # Duplicate credential ID (UNIQUE constraint violation)
        stored_id = custom_credential_id if custom_credential_id else verifiable_credential.get('id', 'unknown')
        logger.warning(f"Credential {stored_id} already exists")
        raise HTTPException(
            status_code=409, 
            detail=f"Credential with ID '{stored_id}' already exists. Use PUT to update or choose a different credentialId."
        )
    except Exception as e:
        logger.error(f"Failed to store credential: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to store credential: {str(e)}")

    return JSONResponse(status_code=201, content=verifiable_credential)


@router.get("/{namespace}/{identifier}/credentials/{credential_id}")
async def get_credential(
    credential_id: str,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency)
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


@router.get("/{namespace}/{identifier}/credentials")
async def list_credentials(
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency),
    revoked: bool = None,
    limit: int = 50,
    offset: int = 0
):
    """List all credentials issued by this DID controller."""
    logger.info(f"=== Listing credentials for {did_controller.namespace}/{did_controller.alias} ===")

    filters = {"scid": did_controller.scid}
    if revoked is not None:
        filters["revoked"] = revoked

    credentials = sql_storage.get_credentials(filters=filters, limit=limit, offset=offset)
    total = sql_storage.count_credentials(filters=filters)

    return JSONResponse(
        status_code=200,
        content={
            "credentials": [c.verifiable_credential for c in credentials],
            "total": total,
            "limit": limit,
            "offset": offset
        }
    )


@router.put("/{namespace}/{identifier}/credentials/{credential_id}")
async def update_credential(
    credential_id: str,
    request_body: CredentialUpload,
    did_controller: DidControllerRecord = Depends(get_did_controller_dependency)
):
    """Update an existing credential."""
    logger.info(f"=== Updating credential {credential_id} ===")

    # Get existing credential from SQL database
    existing_credential = sql_storage.get_credential(credential_id)
    if not existing_credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    # Verify the credential belongs to this DID controller
    if existing_credential.scid != did_controller.scid:
        raise HTTPException(status_code=403, detail="Credential does not belong to this DID")

    # Extract and validate new credential
    verifiable_credential = vars(request_body)["verifiableCredential"].model_dump()
    logger.debug(f"New credential ID: {verifiable_credential.get('id', 'unknown')}")
    
    # Ensure the credential ID matches
    if verifiable_credential.get('id') != credential_id:
        raise HTTPException(status_code=400, detail="Credential ID in body must match URL parameter")
    
    credential = copy.deepcopy(verifiable_credential)
    proofs = credential.pop("proof")
    proofs = proofs if isinstance(proofs, list) else [proofs]
    logger.debug(f"Number of proofs: {len(proofs)}")

    # Extract the issuer proof (from did:webvh:)
    verifiable_credential["proof"] = next(
        (proof for proof in proofs if proof["verificationMethod"].startswith("did:webvh:")), None
    )

    if not verifiable_credential["proof"]:
        logger.error("No valid proof found for credential")
        raise HTTPException(status_code=400, detail="Credential must have a proof from the issuer DID")

    # Verify issuer matches the DID controller
    issuer = verifiable_credential.get("issuer")
    if isinstance(issuer, dict):
        issuer_did = issuer.get("id")
    else:
        issuer_did = issuer
    
    logger.debug(f"Issuer DID: {issuer_did}")
    if issuer_did != did_controller.did:
        logger.error(f"Issuer mismatch: {issuer_did} vs {did_controller.did}")
        raise HTTPException(status_code=400, detail="Issuer DID must match the controller DID")

    # TODO: Implement credential proof verification
    # For now, we skip verification and just update the credential
    logger.debug("Skipping credential proof verification (not implemented)")

    # Update credential in SQL database
    try:
        updated_credential = sql_storage.update_credential(verifiable_credential)
        if not updated_credential:
            raise HTTPException(status_code=404, detail="Credential not found for update")
        logger.info(f"Credential {credential_id} updated successfully")
    except ValueError as e:
        logger.error(f"Invalid credential data: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update credential: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update credential: {str(e)}")

    return JSONResponse(status_code=200, content=verifiable_credential)