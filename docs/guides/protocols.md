# Protocols

The DID WebVH Server implements three core protocols for DID management: connecting to witness services, requesting DID paths, and creating log entries.

## Connecting to a Witness Service

Witnesses advertise their onboarding invitations through the server's DID document. This protocol enables controllers to discover and connect to witness services.

### Protocol Flow

1. **Collect Inputs**
    - WebVH server base URL (e.g., `https://did.example.org`)
    - Witness DID (`did:key:z6Mk...`)

2. **Resolve the Server DID**
    - **GET** `https://did.example.org/.well-known/did.json`
    - The document contains a `service` array generated from the known witness registry
    - Each service entry represents an available witness

3. **Locate the Witness Entry**
    - Find the service object whose `id` matches the witness DID
    - Verify the service `type` is `WitnessInvitation`
    - Extract the `serviceEndpoint` URL

4. **Retrieve the Invitation**
    - The `serviceEndpoint` is a short URL: `https://{domain}/api/invitations?_oobid={witness_key}`
    - **GET** the short URL to retrieve the full invitation as JSON
    - The invitation contains a DIDComm Out-of-Band invitation payload

5. **Establish Connection**
    - Use the invitation URL with your agent/connector to initiate the DIDComm relationship
    - The witness service will handle the connection protocol

### Example

```bash
# 1. Get server DID document
curl https://did.example.org/.well-known/did.json

# Response includes:
{
  "service": [
    {
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "type": "WitnessInvitation",
      "serviceEndpoint": "https://did.example.org/api/invitations?_oobid=z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "name": "Example Witness Service"
    }
  ]
}

# 2. Retrieve invitation from short URL
curl "https://did.example.org/api/invitations?_oobid=z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

# Returns full invitation JSON
{
  "@type": "https://didcomm.org/out-of-band/1.1/invitation",
  "@id": "inv-example-123",
  "label": "Example Witness Service",
  "goal_code": "witness-service",
  "services": [...]
}
```

## Requesting a DID Path

This protocol enables clients to request DID creation parameters from the server. The server returns policy-driven parameters that must be used when creating the DID.

### Protocol Flow

1. **Request Parameters**
    - **GET** `/?namespace={namespace}&alias={alias}`
    - Both `namespace` and `alias` are required query parameters
    - The server validates that the namespace is not reserved
    - The server checks if the alias is already in use

2. **Server Response**
    - Returns policy-driven parameters including:
        - `versionId`: SCID placeholder for the DID
        - `versionTime`: Current timestamp
        - `parameters`: Policy-driven configuration
            - `method`: WebVH method version
            - `witness`: Witness requirements (threshold and witness list)
            - `portable`: Portability setting
            - `updateKeys`: Required update keys
            - `nextKeyHashes`: Prerotation requirements
            - `watchers`: Optional watcher URLs
        - `state`: Initial DID document state
        - `proof`: Proof options for signing

3. **Use Parameters**
    - Client uses these parameters to construct the initial log entry
    - Client must sign the log entry according to the proof options
    - Client must obtain witness signatures if required by policy

### Example

```bash
# Request DID path
curl "https://did.example.org/?namespace=example&alias=my-did"

# Response:
{
  "versionId": "{SCID}",
  "versionTime": "2024-01-15T10:30:00Z",
  "parameters": {
    "method": "did:webvh:1.0",
    "witness": {
      "threshold": 1,
      "witnesses": [
        {"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}
      ]
    },
    "portable": true,
    "updateKeys": [],
    "nextKeyHashes": []
  },
  "state": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:webvh:{SCID}:did.example.org:example:my-did"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod"
  }
}
```

### Error Cases

- **400 Bad Request**: Missing namespace or alias
- **409 Conflict**: Alias already exists
- **400 Bad Request**: Namespace is reserved (e.g., `admin`, `explorer`, `server`, `tails`)

## Creating a Log Entry

This protocol enables clients to create or update DIDs by submitting log entries. Each log entry represents a state change in the DID's history.

### Protocol Flow

1. **Prepare Log Entry**
    - Construct a log entry using parameters from "Requesting a DID Path"
    - Include:
        - `versionId`: Unique identifier for this log entry
        - `versionTime`: Timestamp for this entry
        - `parameters`: Policy parameters (may differ from initial request for updates)
        - `state`: DID document state at this point
        - `proof`: Data Integrity Proof signed by the DID controller

2. **Obtain Witness Signature** (if required)
    - If server policy requires witnesses, request signatures from witness services
    - Witness signs the log entry using their witness key
    - Include witness signature in the request

3. **Submit Log Entry**
    - **POST** `/{namespace}/{alias}`
    - **Body**:
        ```json
        {
          "logEntry": {
            "versionId": "...",
            "versionTime": "...",
            "parameters": {...},
            "state": {...},
            "proof": {...}
          },
          "witnessSignature": {
            "versionId": "...",
            "proof": [...]
          }
        }
        ```

4. **Server Processing**
    - Server validates the log entry structure
    - Server verifies the controller's proof
    - Server verifies witness signatures (if required)
    - Server enforces policy compliance
    - Server updates or creates the DID record

5. **Response**
    - **201 Created**: New DID created successfully
    - **200 OK**: DID updated successfully
    - **400 Bad Request**: Validation error or policy violation

### Example

```bash
# Create initial log entry
curl -X POST "https://did.example.org/example/my-did" \
  -H "Content-Type: application/json" \
  -d '{
    "logEntry": {
      "versionId": "abc123",
      "versionTime": "2024-01-15T10:30:00Z",
      "parameters": {
        "method": "did:webvh:1.0",
        "witness": {
          "threshold": 1,
          "witnesses": [{"id": "did:key:z6Mk..."}]
        }
      },
      "state": {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:webvh:abc123:did.example.org:example:my-did",
        "verificationMethod": [...]
      },
      "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "...",
        "proofValue": "..."
      }
    },
    "witnessSignature": {
      "versionId": "abc123",
      "proof": [{
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6Mk...#witness",
        "proofValue": "..."
      }]
    }
  }'
```

### Policy Enforcement

The server enforces policies during log entry creation:
- **Witness Requirements**: Validates witness signatures match policy requirements
- **Method Version**: Ensures correct WebVH method version
- **Portability**: Validates portability settings
- **Prerotation**: Checks next key hashes if prerotation is required
- **Update Keys**: Validates update key authorization
- **Deactivation**: Handles DID deactivation requests

### Update vs. Create

- **Create**: First log entry for a namespace/alias combination
- **Update**: Subsequent log entries that modify the DID state
- The server automatically determines create vs. update based on existing records





