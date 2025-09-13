import os
import json
import requests
import uuid
import time
from loguru import logger

from operator import itemgetter

AGENT_ADMIN_API_URL = os.getenv('AGENT_ADMIN_API_URL', 'http://witness-agent:8020')
AGENT_ADMIN_API_HEADERS = {
    'X-API-KEY': os.getenv('AGENT_ADMIN_API_KEY', '')
}
WEBVH_SERVER_URL = os.getenv('WEBVH_SERVER_URL', None)

def try_return(request):
    time.sleep(2)
    try:
        return request.json()
    except requests.exceptions.JSONDecodeError:
        logger.info(request.text)
        raise requests.exceptions.JSONDecodeError

def configure_plugin(server_url=WEBVH_SERVER_URL):
    logger.info("Configuring plugin")
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/did/webvh/configuration',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            'server_url': server_url,
            'witness': True,
            'auto_attest': True,
            'endorsement': False
        }
    )
    return try_return(r)

def create_did(namespace):
    logger.info(f"Creating DID in {namespace}")
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/did/webvh/create',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            'options': {
                'apply_policy': 1,
                'witnessThreshold': 1,
                'namespace': namespace,
                'identifier': str(uuid.uuid4())[:6]
            }
        }
    )
    return try_return(r)

def update_did(scid):
    logger.info(f"Updating DID {scid}")
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/did/webvh/update?scid={scid}',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            'did_document': {},
            'options': {}
        }
    )
    return try_return(r)

def deactivate_did(scid):
    logger.info(f"Deactivating DID {scid}")
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/did/webvh/deactivate?scid={scid}',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            'options': {}
        }
    )
    return try_return(r)

def sign_credential(issuer_id, subject_id):
    scid = itemgetter(2)(subject_id.split(":"))
    logger.info(f"Signing credential {scid}")
    issuer_key = issuer_id.split(":")[-1]
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/vc/di/add-proof',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            'document': {
                '@context': [
                    'https://www.w3.org/ns/credentials/v2',
                    'https://www.w3.org/ns/credentials/examples/v2'
                ],
                'type': ['VerifiableCredential', 'ExampleIdentityCredential'],
                'issuer': {
                    'id': issuer_id,
                    'name': 'Example Issuer'
                },
                'credentialSubject': {
                    'id': subject_id,
                    'description': 'Sample VC for WHOIS.vp'
                }
            },
            'options': {
                'type': 'DataIntegrityProof',
                'cryptosuite': 'eddsa-jcs-2022',
                'proofPurpose': 'assertionMethod',
                'verificationMethod': f'{issuer_id}#{issuer_key}'
            }
        }
    )
    return try_return(r)

def sign_presentation(signing_key, credential):
    holder_id = credential.get('credentialSubject').get('id')
    scid = itemgetter(2)(holder_id.split(":"))
    logger.info(f"Signing presentation {scid}")
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/vc/di/add-proof',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            'document': {
                '@context': ['https://www.w3.org/ns/credentials/v2'],
                'type': ['VerifiablePresentation'],
                'holder': holder_id,
                'verifiableCredential': [credential]
            },
            'options': {
                'type': 'DataIntegrityProof',
                'cryptosuite': 'eddsa-jcs-2022',
                'proofPurpose': 'authentication',
                'verificationMethod': f'{holder_id}#{signing_key}'
            }
        }
    )
    return try_return(r)

def upload_whois(vp):
    holder_id = vp.get('holder')
    scid, namespace, alias = itemgetter(2, 4, 5)(holder_id.split(":"))
    logger.info(f"Uploading whois {scid}")
    
    logger.info(json.dumps(vp))
    r = requests.post(
        f'{WEBVH_SERVER_URL}/{namespace}/{alias}/whois',
        json={
            'verifiablePresentation': vp
        }
    )
    return try_return(r)

def create_schema(issuer_id, name='Test Schema', version='1.0', attributes=['test_attribute']):
    scid = itemgetter(2)(issuer_id.split(":"))
    logger.info(f"Creating schema {scid}")
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/anoncreds/schema',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "schema": {
                "attrNames": attributes,
                "issuerId": issuer_id,
                "name": name,
                "version": version
            }
        }
    )
    return try_return(r)

def create_cred_def(schema_id, tag='default', revocation_size=0):
    issuer_id = schema_id.split('/')[0]
    scid = itemgetter(2)(issuer_id.split(":"))
    logger.info(f"Creating cred def {scid}")
    r = requests.post(
        f'{AGENT_ADMIN_API_URL}/anoncreds/credential-definition',
        headers=AGENT_ADMIN_API_HEADERS,
        json={
            "credential_definition": {
                "issuerId": issuer_id,
                "schemaId": schema_id,
                "tag": tag
            },
            "options": {
                "revocation_registry_size": revocation_size,
                "support_revocation": True if revocation_size else False
            }
            }
    )
    return try_return(r)
    

logger.info('Configuring Agent')
webvh_config = configure_plugin(WEBVH_SERVER_URL)
witness_id = webvh_config.get('witnesses')[0]
logger.info(f'Witness Configured: {witness_id}')
logger.info('Provisioning Server')
for namespace in ['ns-01', 'ns-02', 'ns-03']:
    for idx in range(2):
        time.sleep(2)
        log_entry = create_did(namespace)
        scid = log_entry.get('parameters', {}).get('scid')
        did = log_entry.get('state', {}).get('id')
        signing_key = log_entry.get('state', {}).get('verificationMethod')[0].get('publicKeyMultibase')
        logger.info(signing_key)
        update_did(scid)
        update_did(scid)
        vc = sign_credential(witness_id, did).get('securedDocument')
        vp = sign_presentation(signing_key, vc).get('securedDocument')
        whois = upload_whois(vp)
        schema = create_schema(did)
        schema_id = schema.get('schema_state', {}).get('schema_id', None)
        cred_def = create_cred_def(schema_id, revocation_size=10)
        cred_def_id = cred_def.get('credential_definition_state', {}).get('credential_definition_id', None)
        if idx == 1:
            deactivate_did(scid)