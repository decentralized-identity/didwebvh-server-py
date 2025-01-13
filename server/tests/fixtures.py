from config import settings
from app.models.did_document import DidDocument, SecuredDidDocument
from app.models.di_proof import DataIntegrityProof

TEST_SEED = "ixUwS8A2SYzmPiGor7t08wgg1ifNABrB"
TEST_AUTHORISED_KEY = "z6Mkixacx8HJ5nRBJvJKNdv83v1ejZBpz3HvRCfa2JaKbQJV"
TEST_AUTHORISED_JWK = "QvGYHF-i-RTVnJlSDsYkSffG1GUZasgGt1yhRdv4rgI"
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
    context=["https://www.w3.org/ns/did/v1"], id=TEST_DID
).model_dump()
