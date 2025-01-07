from config import settings

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
TEST_DID_DOCUMENT = {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
    ],
    "id": TEST_DID,
    "authorisation": [
        f'{TEST_DID}#key-01'
    ],
    "assertionMethod": [
        f'{TEST_DID}#key-01'
    ],
    "verificationMethod": [
        {
            'id': f'{TEST_DID}#key-01',
            'type': 'Multikey',
            'controller': TEST_DID,
            'publiKeyMultibase': TEST_AUTHORISED_KEY
        }
    ],
}
TEST_DID_DOCUMENT_SIGNED = {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
    ],
    "id": TEST_DID,
    "authorisation": [
        f'{TEST_DID}#key-01'
    ],
    "assertionMethod": [
        f'{TEST_DID}#key-01'
    ],
    "verificationMethod": [
        {
            'id': f'{TEST_DID}#key-01',
            'type': 'Multikey',
            'controller': TEST_DID,
            'publiKeyMultibase': TEST_AUTHORISED_KEY
        }
    ],
    "proof": {
        "type": "DataIntegrityProof",
        "proofPurpose": "assertionMethod",
        "verificationMethod": f"did:key:{TEST_AUTHORISED_KEY}#{TEST_AUTHORISED_KEY}",
        "cryptosuite": "eddsa-jcs-2022",
        "proofValue": "z3Th9TRHPiwErjPFC9oNEvhsnkEGKEyipR7c6db2gUZxBb6EtgntsXF7ANr1ByC2aUE1igFxtswfpZyTKXCe1ZMs2"
      }
}