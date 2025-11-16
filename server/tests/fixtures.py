import base64
import json

from app.models.did_document import DidDocument
from config import settings
from app.models.did_document import VerificationMethodMultikey
from app.models.policy import ActivePolicy


TEST_SIGNING_SEED = "ixUwS8A2SYzmPiGor7t08wgg1ifNABrB"
TEST_SIGNING_KEY = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"

TEST_UPDATE_SEED = "ixUwS8A2SYzmPiGor7t08wgg1ifNABrB"
TEST_UPDATE_KEY = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"

# Known witness (registered in TEST_WITNESS_REGISTRY)
TEST_WITNESS_SEED = "ixUwS8A2SYzmPiGor7t08wgg1ifNABrB"
TEST_WITNESS_KEY = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"
TEST_WITNESS_INVITATION_PAYLOAD = {
    "@type": "https://didcomm.org/out-of-band/1.1/invitation",
    "@id": "test-invitation",
    "label": "Test Witness",
    "services": [
        {
            "id": "#inline",
            "type": "did-communication",
            "serviceEndpoint": "https://witness.example.com/agent",
            "recipientKeys": ["did:key:z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV#test-key"],
        }
    ],
}
_encoded_invitation = (
    base64.urlsafe_b64encode(json.dumps(TEST_WITNESS_INVITATION_PAYLOAD).encode("utf-8"))
    .decode("utf-8")
    .rstrip("=")
)
TEST_WITNESS_INVITATION_URL = f"https://witness.example.com/oob-invite?oob={_encoded_invitation}"
TEST_WITNESS_SERVICE_ENDPOINT = f"https://{settings.DOMAIN}?_oobid={TEST_WITNESS_KEY}"

# Known witness (same as above, for clarity)
TEST_KNOWN_WITNESS_SEED = TEST_WITNESS_SEED
TEST_KNOWN_WITNESS_KEY = TEST_WITNESS_KEY

# Unknown witness (NOT registered in TEST_WITNESS_REGISTRY)
TEST_UNKNOWN_WITNESS_SEED = "UnknownWitnessSeed456NotInRegistry"
TEST_UNKNOWN_WITNESS_KEY = (
    "z6MkgCqLkVrGZfctHXYXNyXvqPXJdPJeP39Mk67N9AEL2vP8"  # Generated from seed above
)

TEST_NEXT_SEED = "ixUwS8A2SYzmPiGor7t08wgg1ifNABrB"
TEST_NEXT_KEY = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"
TEST_NEXT_KEY_HASH = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"

TEST_DOMAIN = settings.DOMAIN
TEST_DID_NAMESPACE = "test"
TEST_DID_IDENTIFIER = "01"
TEST_SCID = "QmQHoxuyZznVkAimy3f4qst66UNAjUMXzgLn4tfavPSSSE"
TEST_PLACEHOLDER_ID = (
    r"did:webvh:{SCID}:" + f"{TEST_DOMAIN}:{TEST_DID_NAMESPACE}:{TEST_DID_IDENTIFIER}"
)
TEST_DID = f"did:webvh:{TEST_SCID}:{TEST_DOMAIN}:{TEST_DID_NAMESPACE}:{TEST_DID_IDENTIFIER}"
TEST_PROOF_OPTIONS = {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
}
TEST_VERIFICATION_METHOD = {
    "id": f"{TEST_DID}#{TEST_SIGNING_KEY}",
    "type": "Multikey",
    "controller": TEST_DID,
    "publicKeyMultibase": TEST_SIGNING_KEY,
}
TEST_VERSION_TIME = "2025-06-19T03:09:19Z"
TEST_UPDATE_TIME = "2025-06-19T03:10:19Z"

TEST_LOG_ENTRY = {}

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

TEST_POLICY = ActivePolicy(
    version="1.0",
    witness=True,
    watcher=None,
    portability=False,
    prerotation=False,
    endorsement=False,
    validity=0,
    witness_registry_url=None,
).model_dump()

TEST_WITNESS_REGISTRY = {
    f"did:key:{TEST_WITNESS_KEY}": {
        "name": "Test Witness",
        "serviceEndpoint": TEST_WITNESS_SERVICE_ENDPOINT,
    }
}
TEST_ANONCREDS_SCHEMA = {"name": "test", "version": "1.0", "attributes": ["test_attribute"]}

TEST_PARAMETERS = {}
TEST_STATE = {}
