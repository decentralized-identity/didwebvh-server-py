from config import settings
from app.models.did_document import DidDocument, SecuredDidDocument
from app.models.di_proof import DataIntegrityProof

TEST_DOMAIN = settings.DOMAIN
TEST_DID_NAMESPACE = 'test'
TEST_DID_IDENTIFIER = '01'
TEST_DID = f"{settings.DID_WEB_BASE}:{TEST_DID_NAMESPACE}:{TEST_DID_IDENTIFIER}"
TEST_PROOF_OPTIONS = {
    'type': 'DataIntegrityProof',
    'cryptosuite': 'eddsa-jcs-2022',
    'proofPurpose': 'assertionMethod'
}
TEST_AUTHORISED_KEY = 'z6Mkj8h3kzWZrPiucoyY9LGCTpXhCqBoX3doDmHz5MaPxnvi'
TEST_AUTHORISED_JWK = 'RYirjVOuAh9BXxQaxozaDLK_JqrKPicZeq9bl3Fg8xc'

TEST_DID_DOCUMENT = DidDocument(
    context=['https://www.w3.org/ns/did/v1'],
    id=TEST_DID
).model_dump()

TEST_DID_DOCUMENT_PROOF = DataIntegrityProof(
    proofValue='z4NCh2bocHncp9SSpCDETSsWN5ueu7eLPFgaVTNvgCk2RxZvFbVHAN8keGqd8XXbSzrxd3q1VMKQrZuqf672WNncK',
    verificationMethod=f'did:key:{TEST_AUTHORISED_KEY}#{TEST_AUTHORISED_KEY}'
).model_dump()

TEST_DID_DOCUMENT_SIGNED = SecuredDidDocument(
    context=['https://www.w3.org/ns/did/v1'],
    id=TEST_DID,
    proof=TEST_DID_DOCUMENT_PROOF
).model_dump()