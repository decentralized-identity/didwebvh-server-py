from app.models.did_document import DidDocument
from config import settings
from app.models.did_document import DidDocument, VerificationMethodMultikey
from app.models.di_proof import DataIntegrityProof

TEST_WITNESS_SEED = "R9b6JZegNAOyV6Tz0ysIIemZv4cd0VjW"


TEST_SIGNING_SEED = "ixUwS8A2SYzmPiGor7t08wgg1ifNABrB"
TEST_SIGNING_KEY = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"

TEST_REGISTRATION_SEED = "ixUwS8A2SYzmPiGor7t08wgg1ifNABrB"
TEST_REGISTRATION_KEY = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"

TEST_DOMAIN = settings.DOMAIN
TEST_DID_NAMESPACE = "test"
TEST_DID_IDENTIFIER = "01"
TEST_DID = f"{settings.DID_WEB_BASE}:{TEST_DID_NAMESPACE}:{TEST_DID_IDENTIFIER}"
TEST_PROOF_OPTIONS = {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
}

TEST_DID_DOCUMENT = DidDocument(
    context=["https://www.w3.org/ns/did/v1"],
    id=TEST_DID,
    verificationMethod=[
        VerificationMethodMultikey(
            id=f"{TEST_DID}#key-0",
            type="Multikey",
            controller=TEST_DID,
            publicKeyMultibase=TEST_SIGNING_KEY,
        )
    ],
).model_dump()


TEST_ANONCREDS_SCHEMA = {"name": "test", "version": "1.0", "attributes": ["test_attribute"]}
