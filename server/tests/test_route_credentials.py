"""Unit tests for the credentials endpoints."""

import json
import base64
import pytest
from fastapi.testclient import TestClient
from aries_askar import Key, KeyAlg
from aries_askar.bindings import LocalKeyHandle
from multiformats import multibase

from app import app
from app.plugins.storage import StorageManager
from tests.fixtures import (
    TEST_DID_NAMESPACE,
    TEST_POLICY,
    TEST_WITNESS_REGISTRY,
    TEST_UPDATE_SEED,
)
from tests.mock_agents import WitnessAgent, ControllerAgent
from tests.helpers import (
    create_unique_did,
    setup_controller_with_verification_method,
    create_test_namespace_and_identifier,
    assert_error_response,
)

# Setup test agents
witness = WitnessAgent()
controller = ControllerAgent()


@pytest.fixture(autouse=True)
async def setup_database():
    """Set up the database before each test."""
    storage = StorageManager()
    await storage.provision(recreate=True)

    # Store policy and registry in database
    storage.create_or_update_policy("active", TEST_POLICY)
    storage.create_or_update_registry(
        registry_id="knownWitnesses",
        registry_type="witnesses",
        registry_data=TEST_WITNESS_REGISTRY,
        meta={"created": "2024-01-01T00:00:00Z", "updated": "2024-01-01T00:00:00Z"},
    )
    yield


def create_jwt_credential(issuer_did: str, signing_key, verification_method_id: str, credential_type: str = "TestCredential") -> tuple:
    """
    Create a test JWT-based EnvelopedVerifiableCredential with real signature.
    
    Args:
        issuer_did: DID of the issuer
        signing_key: Askar Key object to sign the JWT
        verification_method_id: Full verification method ID (did#key)
        credential_type: Type of credential to create
        
    Returns:
        Tuple of (enveloped_credential, decoded_credential)
    """
    import time
    from aries_askar import Key
    
    # Create the actual credential payload (must be a complete VC)
    payload = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": f"http://example.com/credentials/{credential_type.lower()}-{int(time.time()*1000000)}",
        "type": ["VerifiableCredential", credential_type],
        "issuer": {"id": issuer_did, "name": "Test Issuer"},
        "credentialSubject": {
            "id": "did:example:subject123",
            "name": "Test Subject",
            "email": "test@example.com"
        },
        "validFrom": "2024-01-01T00:00:00Z",
        "validUntil": "2025-01-01T00:00:00Z"
    }
    
    # Create JWT header
    header = {"alg": "EdDSA", "typ": "JWT", "kid": verification_method_id}
    
    # Encode to JWT
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    # Sign the JWT (EdDSA signs header.payload)
    to_sign = f"{header_b64}.{payload_b64}".encode()
    signature_bytes = signing_key.sign_message(to_sign)
    signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')
    
    jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    # Create EnvelopedVerifiableCredential with VC-JOSE format
    enveloped_vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": f"data:application/vc+jwt,{jwt_token}",
        "type": ["EnvelopedVerifiableCredential"]
    }
    
    return enveloped_vc, payload


def create_regular_credential(issuer_did: str, credential_type: str = "TestCredential", unique_id: str = None) -> dict:
    """
    Create a test regular VerifiableCredential (not enveloped).
    
    Args:
        issuer_did: DID of the issuer
        credential_type: Type of credential to create
        unique_id: Optional unique identifier to make the credential ID unique
        
    Returns:
        Regular verifiable credential
    """
    import time
    # Make credential ID unique by using timestamp
    id_suffix = unique_id or str(int(time.time() * 1000000))
    
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": f"http://example.com/credentials/{credential_type.lower()}-{id_suffix}",
        "type": ["VerifiableCredential", credential_type],
        "issuer": {"id": issuer_did, "name": "Test Issuer"},
        "credentialSubject": {
            "id": "did:example:subject456",
            "name": "Another Test Subject",
            "organization": "Test Org"
        },
        "validFrom": "2024-01-01T00:00:00Z",
        "validUntil": "2025-01-01T00:00:00Z",
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-2022",
            "verificationMethod": f"{issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGesjuTSwRdoWhAfGFCF5bppETSTojQCrfFPP2oumHKtz"
        }
    }


class TestPublishCredential:
    """Test cases for publishing verifiable credentials."""

    @pytest.mark.asyncio
    async def test_publish_enveloped_vc_success(self):
        """Test successful EnvelopedVerifiableCredential (VC-JOSE) upload."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-enveloped-01")

        with TestClient(app) as test_client:
            # Create DID and add verification method
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            controller_agent, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_identifier, doc_state
            )

            # Get signing key from controller agent
            signing_key = controller_agent.update_key

            # Create EnvelopedVC with valid VC-JOSE format
            enveloped_vc, payload = create_jwt_credential(did_id, signing_key, verification_method_id, "DriverLicense")

            # Publish credential
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": enveloped_vc}
            )
            
            assert response.status_code == 201
            published_vc = response.json()
            
            # Verify the envelope was returned
            assert published_vc["type"] == ["EnvelopedVerifiableCredential"]
            assert published_vc["id"].startswith("data:application/vc+jwt,")

    @pytest.mark.asyncio
    async def test_publish_enveloped_vc_with_custom_id(self):
        """Test EnvelopedVC upload with custom credential ID."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-custom-id-01")

        with TestClient(app) as test_client:
            # Create DID and add verification method
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            controller_agent, verification_method_id = setup_controller_with_verification_method(
                test_client, test_namespace, test_identifier, doc_state
            )
            
            # Get signing key from controller agent
            signing_key = controller_agent.update_key
            
            enveloped_vc, payload = create_jwt_credential(did_id, signing_key, verification_method_id, "HealthCard")
            custom_id = "my-custom-health-card-001"

            # Publish with custom ID in options
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={
                    "verifiableCredential": enveloped_vc,
                    "options": {"credentialId": custom_id}
                }
            )
            
            assert response.status_code == 201

            # Verify we can retrieve it by custom ID
            response = test_client.get(
                f"/{test_namespace}/{test_identifier}/credentials/{custom_id}"
            )
            assert response.status_code == 200
            retrieved = response.json()
            assert retrieved["id"].startswith("data:application/vc+jwt,")

    @pytest.mark.asyncio
    async def test_publish_regular_vc_success(self):
        """Test successful regular VerifiableCredential upload."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-regular-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            regular_vc = create_regular_credential(did_id, "UniversityDegree")

            # Publish credential
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": regular_vc}
            )
            
            assert response.status_code == 201
            published_vc = response.json()
            
            assert "UniversityDegree" in published_vc["type"]
            assert published_vc["id"] == regular_vc["id"]

    @pytest.mark.asyncio
    async def test_publish_duplicate_credential_fails(self):
        """Test that publishing a duplicate credential fails with 409."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-duplicate-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            regular_vc = create_regular_credential(did_id, "TestCred")

            # Publish first time
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": regular_vc}
            )
            assert response.status_code == 201

            # Try to publish again
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": regular_vc}
            )
            assert response.status_code == 409
            assert "already exists" in response.json()["detail"]


class TestEnvelopedVCValidation:
    """Test cases for EnvelopedVerifiableCredential media type validation."""

    @pytest.mark.asyncio
    async def test_enveloped_vc_invalid_media_type_ld_json(self):
        """Test that ld+json media type is rejected for EnvelopedVC."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-invalid-ld-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Create EnvelopedVC with INVALID media type (ld+json instead of jwt)
            invalid_vc = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "data:application/vc+ld+json,{\"test\":\"data\"}",
                "type": ["EnvelopedVerifiableCredential"]
            }

            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": invalid_vc}
            )
            
            assert response.status_code == 400
            error = response.json()["detail"]
            assert "application/vc+jwt" in error
            assert "application/vc+ld+json" in error
            assert "VC-JOSE" in error

    @pytest.mark.asyncio
    async def test_enveloped_vc_invalid_media_type_plain_json(self):
        """Test that plain json media type is rejected for EnvelopedVC."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-invalid-json-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            invalid_vc = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "data:application/json,{\"test\":\"data\"}",
                "type": ["EnvelopedVerifiableCredential"]
            }

            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": invalid_vc}
            )
            
            assert response.status_code == 400
            error = response.json()["detail"]
            assert "application/vc+jwt" in error
            assert "application/json" in error

    @pytest.mark.asyncio
    async def test_enveloped_vc_missing_data_url(self):
        """Test that EnvelopedVC without data URL is rejected."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-no-data-url-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # EnvelopedVC with HTTP URL instead of data URL
            invalid_vc = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "http://example.com/credentials/123",
                "type": ["EnvelopedVerifiableCredential"]
            }

            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": invalid_vc}
            )
            
            assert response.status_code == 400
            error = response.json()["detail"]
            assert "data URL" in error
            assert "application/vc+jwt" in error

    @pytest.mark.asyncio
    async def test_enveloped_vc_malformed_jwt(self):
        """Test that EnvelopedVC with malformed JWT is rejected."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-malformed-jwt-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Valid media type but malformed JWT (only 2 parts instead of 3)
            invalid_vc = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "data:application/vc+jwt,header.payload",  # Missing signature
                "type": ["EnvelopedVerifiableCredential"]
            }

            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": invalid_vc}
            )
            
            # Should fail at storage layer when trying to decode
            assert response.status_code == 500  # Internal error during decoding


class TestGetCredential:
    """Test cases for retrieving credentials."""

    @pytest.mark.asyncio
    async def test_get_credential_success(self):
        """Test successful credential retrieval."""
        import urllib.parse
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-get-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            regular_vc = create_regular_credential(did_id, "TestCred")
            credential_id = regular_vc["id"]

            # Publish credential
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": regular_vc}
            )
            assert response.status_code == 201

            # Retrieve credential (URL encode the ID)
            encoded_id = urllib.parse.quote(credential_id, safe='')
            response = test_client.get(
                f"/{test_namespace}/{test_identifier}/credentials/{encoded_id}"
            )
            
            assert response.status_code == 200
            retrieved = response.json()
            assert retrieved["id"] == credential_id
            assert "TestCred" in retrieved["type"]

    @pytest.mark.asyncio
    async def test_get_credential_not_found(self):
        """Test retrieving non-existent credential returns 404."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-get-notfound-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)

            response = test_client.get(
                f"/{test_namespace}/{test_identifier}/credentials/nonexistent-id"
            )
            
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_credential_wrong_did(self):
        """Test retrieving credential from wrong DID returns 403."""
        import urllib.parse
        test_namespace1, test_identifier1 = create_test_namespace_and_identifier("cred-wrong-did-01")
        test_namespace2, test_identifier2 = create_test_namespace_and_identifier("cred-wrong-did-02")

        with TestClient(app) as test_client:
            # Create two DIDs
            did_id1, doc_state1 = create_unique_did(test_client, test_namespace1, test_identifier1)
            did_id2, doc_state2 = create_unique_did(test_client, test_namespace2, test_identifier2)
            
            # Publish credential to DID 1
            regular_vc = create_regular_credential(did_id1, "TestCred")
            credential_id = regular_vc["id"]
            
            response = test_client.post(
                f"/{test_namespace1}/{test_identifier1}/credentials",
                json={"verifiableCredential": regular_vc}
            )
            assert response.status_code == 201

            # Try to retrieve from DID 2 (URL encode the ID)
            encoded_id = urllib.parse.quote(credential_id, safe='')
            response = test_client.get(
                f"/{test_namespace2}/{test_identifier2}/credentials/{encoded_id}"
            )
            
            assert response.status_code == 403
            assert "does not belong" in response.json()["detail"]


class TestListCredentials:
    """Test cases for listing credentials."""

    @pytest.mark.asyncio
    async def test_list_credentials_success(self):
        """Test listing credentials with pagination."""
        import time
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-list-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Publish multiple credentials with unique IDs
            for i in range(5):
                vc = create_regular_credential(did_id, f"TestCred{i}", unique_id=f"list-{i}-{int(time.time()*1000000)}")
                response = test_client.post(
                    f"/{test_namespace}/{test_identifier}/credentials",
                    json={"verifiableCredential": vc}
                )
                assert response.status_code == 201

            # List credentials
            response = test_client.get(
                f"/{test_namespace}/{test_identifier}/credentials"
            )
            
            assert response.status_code == 200
            result = response.json()
            assert result["total"] == 5
            assert len(result["credentials"]) == 5
            assert result["limit"] == 50
            assert result["offset"] == 0

    @pytest.mark.asyncio
    async def test_list_credentials_with_pagination(self):
        """Test credential listing with custom pagination."""
        import time
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-list-page-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Publish 10 credentials with unique IDs
            for i in range(10):
                vc = create_regular_credential(did_id, f"TestCred{i}", unique_id=f"page-{i}-{int(time.time()*1000000)}")
                response = test_client.post(
                    f"/{test_namespace}/{test_identifier}/credentials",
                    json={"verifiableCredential": vc}
                )
                assert response.status_code == 201

            # List with custom limit
            response = test_client.get(
                f"/{test_namespace}/{test_identifier}/credentials?limit=3&offset=0"
            )
            
            assert response.status_code == 200
            result = response.json()
            assert result["total"] == 10
            assert len(result["credentials"]) == 3
            assert result["limit"] == 3

    @pytest.mark.asyncio
    async def test_list_credentials_filter_by_revoked(self):
        """Test filtering credentials by revoked status."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-list-revoked-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Publish credentials
            vc = create_regular_credential(did_id, "ActiveCred")
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": vc}
            )
            assert response.status_code == 201

            # List non-revoked credentials
            response = test_client.get(
                f"/{test_namespace}/{test_identifier}/credentials?revoked=false"
            )
            
            assert response.status_code == 200
            result = response.json()
            assert result["total"] >= 1

    @pytest.mark.asyncio
    async def test_list_credentials_empty(self):
        """Test listing credentials when none exist."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-list-empty-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)

            response = test_client.get(
                f"/{test_namespace}/{test_identifier}/credentials"
            )
            
            assert response.status_code == 200
            result = response.json()
            assert result["total"] == 0
            assert len(result["credentials"]) == 0


class TestCredentialValidation:
    """Test cases for credential validation."""

    @pytest.mark.asyncio
    async def test_publish_credential_missing_type(self):
        """Test that credential without type is rejected."""
        import time
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-no-type-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Credential without type
            invalid_vc = {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "id": f"http://example.com/credentials/no-type-{int(time.time()*1000000)}",
                "issuer": did_id
            }

            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": invalid_vc}
            )
            
            assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_publish_credential_missing_id(self):
        """Test that credential without ID is rejected."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("cred-no-id-01")

        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Credential without id
            invalid_vc = {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": did_id,
                "credentialSubject": {"id": "did:example:subject"}
            }

            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": invalid_vc}
            )
            
            # Should fail at storage layer (500 because storage throws ValueError)
            assert response.status_code in [400, 500]

    @pytest.mark.asyncio
    async def test_publish_credential_to_nonexistent_did(self):
        """Test that publishing to non-existent DID returns 404."""
        with TestClient(app) as test_client:
            response = test_client.post(
                "/nonexistent/namespace/credentials",
                json={"verifiableCredential": {"id": "test", "type": ["VerifiableCredential"]}}
            )
            
            assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_publish_enveloped_vc_missing_context_in_jwt(self):
        """Test that EnvelopedVC with missing @context in JWT payload is rejected."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("env-no-ctx")
        
        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Create JWT with missing @context
            payload = {
                "id": "http://example.com/credentials/test-123",
                "type": ["VerifiableCredential", "TestCredential"],
                "issuer": {"id": did_id},
                "credentialSubject": {"id": "did:example:subject"}
            }
            header = {"alg": "ES256", "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            jwt_token = f"{header_b64}.{payload_b64}.fake_sig"
            
            enveloped_vc = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": f"data:application/vc+jwt,{jwt_token}",
                "type": ["EnvelopedVerifiableCredential"]
            }
            
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": enveloped_vc}
            )
            
            assert response.status_code == 500
            assert "@context" in response.text or "context" in response.text.lower()

    @pytest.mark.asyncio
    async def test_publish_enveloped_vc_missing_type_in_jwt(self):
        """Test that EnvelopedVC with missing type in JWT payload is rejected."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("env-no-type")
        
        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Create JWT with missing type
            payload = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "http://example.com/credentials/test-123",
                "issuer": {"id": did_id},
                "credentialSubject": {"id": "did:example:subject"}
            }
            header = {"alg": "ES256", "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            jwt_token = f"{header_b64}.{payload_b64}.fake_sig"
            
            enveloped_vc = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": f"data:application/vc+jwt,{jwt_token}",
                "type": ["EnvelopedVerifiableCredential"]
            }
            
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": enveloped_vc}
            )
            
            assert response.status_code == 500
            assert "type" in response.text.lower()

    @pytest.mark.asyncio
    async def test_publish_enveloped_vc_invalid_type_in_jwt(self):
        """Test that EnvelopedVC with type not including VerifiableCredential is rejected."""
        test_namespace, test_identifier = create_test_namespace_and_identifier("env-bad-type")
        
        with TestClient(app) as test_client:
            did_id, doc_state = create_unique_did(test_client, test_namespace, test_identifier)
            
            # Create JWT with wrong type
            payload = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "http://example.com/credentials/test-123",
                "type": ["SomeOtherType"],  # Missing VerifiableCredential
                "issuer": {"id": did_id},
                "credentialSubject": {"id": "did:example:subject"}
            }
            header = {"alg": "ES256", "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            jwt_token = f"{header_b64}.{payload_b64}.fake_sig"
            
            enveloped_vc = {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": f"data:application/vc+jwt,{jwt_token}",
                "type": ["EnvelopedVerifiableCredential"]
            }
            
            response = test_client.post(
                f"/{test_namespace}/{test_identifier}/credentials",
                json={"verifiableCredential": enveloped_vc}
            )
            
            assert response.status_code == 500
            assert "VerifiableCredential" in response.text

