# API Endpoints

## Server Endpoints

### Root Endpoint

- **GET** `/`
  - **Purpose**: Multi-purpose endpoint for DID requests and invitation lookup
  - **Query Parameters**:
    - `namespace` (optional): Namespace for DID creation
    - `alias` (optional): Alias for DID creation
    - `_oobid` (optional): Witness key for invitation lookup
  - **Behavior**:
    - If `_oobid` is provided: Returns the stored invitation as JSON
    - If `namespace` and `alias` are provided: Returns DID creation parameters
    - Otherwise: Redirects to `/explorer`

### Server Status

- **GET** `/server/status`
  - Returns server status and domain information

### DID Document

- **GET** `/.well-known/did.json`
  - Returns the server's DID document with witness services

## Identifier Endpoints

### Request DID Parameters

- **GET** `/?namespace={namespace}&alias={alias}`
  - Returns policy-driven parameters for DID creation
  - Includes witness requirements, method version, and other policy settings

### Create/Update DID

- **POST** `/{namespace}/{alias}`
  - **Body**: `{ "logEntry": <history_line>, "witnessSignature": <optional_proof> }`
  - Creates or updates a DID with a new log entry
  - Validates signatures and enforces policy

### Resolve DID

- **GET** `/{namespace}/{alias}/did.json`
  - Returns the current DID document

- **GET** `/{namespace}/{alias}/did.jsonl`
  - Returns the DID log history

- **GET** `/{namespace}/{alias}/did-witness.json`
  - Returns witness signatures for the DID

- **GET** `/{namespace}/{alias}/whois.vp`
  - Returns the WHOIS Verifiable Presentation

## Resource Endpoints

- **POST** `/{namespace}/{alias}/resources`
  - Upload an attested resource
  - **Body**: `{ "attestedResource": <resource_with_proof> }`

- **GET** `/{namespace}/{alias}/resources/{resource_id}`
  - Retrieve a specific resource

## Credential Endpoints

- **POST** `/{namespace}/{alias}/credentials`
  - Upload a verifiable credential
  - **Body**: `{ "verifiableCredential": <vc>, "options": { "credentialId": <id> } }`

- **GET** `/{namespace}/{alias}/credentials/{credential_id}`
  - Retrieve a specific credential





