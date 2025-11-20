# API Endpoints

Complete API reference with request and response examples for all endpoints.

## Authentication

Administrative endpoints require authentication via API key in the header:

```http
x-api-key: your-api-key-here
```

## Server Endpoints

### Root Endpoint

**GET** `/`

Multi-purpose endpoint for DID requests and explorer redirect.

**Query Parameters:**

- `namespace` (optional): Namespace for DID creation
- `alias` (optional): Alias for DID creation

**Examples:**

**Request DID Parameters:**
```http
GET /?namespace=example&alias=my-did
```

**Response:**
```json
{
  "state": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:webvh:example.com:example:my-did"
  },
  "parameters": {
    "version": "1.0",
    "witness": {
      "threshold": 1,
      "witnesses": [
        {
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }
      ]
    },
    "updateKeys": ["z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
  }
}
```

**Default Redirect:**
If no query parameters are provided, redirects to `/api/explorer`.

### Server Status

**GET** `/api/server/status`

Returns server status and domain information.

**Response:**
```json
{
  "status": "online",
  "domain": "did.example.org",
  "version": "1.0"
}
```

### Server DID Document

**GET** `/.well-known/did.json`

Returns the server's DID document with witness services.

**Response:**
```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:example.com",
  "service": [
    {
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "type": "WitnessInvitation",
      "name": "Example Witness Service",
      "serviceEndpoint": "https://example.com/api/invitations?_oobid=z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    }
  ]
}
```

## Identifier Endpoints

### Create/Update DID

**POST** `/{namespace}/{alias}`

Creates a new DID or updates an existing one with a new log entry.

**Request Body:**
```json
{
  "logEntry": {
    "versionId": "2024-01-01T00:00:00Z",
    "parameters": {
      "version": "1.0",
      "witness": {
        "threshold": 1,
        "witnesses": [
          {
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
          }
        ]
      },
      "updateKeys": ["z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
    },
    "state": {
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": "did:webvh:example.com:example:my-did",
      "verificationMethod": [
        {
          "id": "did:webvh:example.com:example:my-did#key-1",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:webvh:example.com:example:my-did",
          "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }
      ],
      "assertionMethod": ["did:webvh:example.com:example:my-did#key-1"]
    },
    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      }
    ]
  },
  "witnessSignature": {
    "versionId": "2024-01-01T00:00:00Z",
    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      }
    ]
  }
}
```

**Response (201 Created for new DID):**
```json
{
  "versionId": "2024-01-01T00:00:00Z",
  "parameters": {
    "version": "1.0",
    "witness": {
      "threshold": 1,
      "witnesses": [
        {
          "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }
      ]
    },
    "updateKeys": ["z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"]
  },
  "state": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:webvh:example.com:example:my-did",
    "verificationMethod": [
      {
        "id": "did:webvh:example.com:example:my-did#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:webvh:example.com:example:my-did",
        "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      }
    ],
    "assertionMethod": ["did:webvh:example.com:example:my-did#key-1"]
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2024-01-01T00:00:00Z",
      "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z..."
    }
  ]
}
```

**Response (200 OK for update):**
Same structure as above, with updated `versionId` and `state`.

### Update WHOIS

**POST** `/{namespace}/{alias}/whois`

Updates the WHOIS Verifiable Presentation.

**Request Body:**
```json
{
  "verifiablePresentation": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": [
      {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "credentialSubject": {
          "id": "did:webvh:example.com:example:my-did",
          "namespace": "example",
          "alias": "my-did",
          "contact": "contact@example.com"
        },
        "proof": {
          "type": "DataIntegrityProof",
          "cryptosuite": "eddsa-rdfc-2022",
          "created": "2024-01-01T00:00:00Z",
          "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
          "proofPurpose": "assertionMethod",
          "proofValue": "z..."
        }
      }
    ],
    "proof": {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2024-01-01T00:00:00Z",
      "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
      "proofPurpose": "authentication",
      "proofValue": "z..."
    }
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "WHOIS updated successfully"
}
```

## Resource Endpoints

### Upload Attested Resource

**POST** `/{namespace}/{alias}/resources`

Uploads an attested resource bound to a DID.

**Request Body:**
```json
{
  "attestedResource": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/data-integrity/v1"
    ],
    "type": ["AttestedResource"],
    "id": "did:webvh:example.com:example:my-did:resource:abc123",
    "resourceContent": {
      "schema": {
        "name": "ExampleSchema",
        "version": "1.0",
        "attrNames": ["name", "age"]
      }
    },
    "resourceMetadata": {
      "name": "Example Schema",
      "description": "An example AnonCreds schema"
    },
    "proof": [
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      },
      {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2024-01-01T00:00:00Z",
        "verificationMethod": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      }
    ]
  },
  "options": {
    "resourceId": "abc123",
    "resourceName": "Example Schema",
    "resourceType": "anoncreds/schema"
  }
}
```

**Response (201 Created):**
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/data-integrity/v1"
  ],
  "type": ["AttestedResource"],
  "id": "did:webvh:example.com:example:my-did:resource:abc123",
  "resourceContent": {
    "schema": {
      "name": "ExampleSchema",
      "version": "1.0",
      "attrNames": ["name", "age"]
    }
  },
  "resourceMetadata": {
    "name": "Example Schema",
    "description": "An example AnonCreds schema"
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2024-01-01T00:00:00Z",
      "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z..."
    }
  ]
}
```

### Get Resource

**GET** `/{namespace}/{alias}/resources/{resource_id}`

Retrieves a specific resource by ID.

**Example Request:**
```http
GET /example/my-did/resources/abc123
```

**Response:**
```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/data-integrity/v1"
  ],
  "type": ["AttestedResource"],
  "id": "did:webvh:example.com:example:my-did:resource:abc123",
  "resourceContent": {
    "schema": {
      "name": "ExampleSchema",
      "version": "1.0",
      "attrNames": ["name", "age"]
    }
  },
  "resourceMetadata": {
    "name": "Example Schema",
    "description": "An example AnonCreds schema"
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2024-01-01T00:00:00Z",
      "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z..."
    }
  ]
}
```

### Update Resource

**PUT** `/{namespace}/{alias}/resources/{resource_id}`

Updates an existing resource.

**Request Body:**
Same structure as upload, with updated content and new proof.

**Response:**
Same as upload response (200 OK).

## Credential Endpoints

### Upload Verifiable Credential

**POST** `/{namespace}/{alias}/credentials`

Uploads a verifiable credential.

**Request Body:**
```json
{
  "verifiableCredential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/security/data-integrity/v1"
    ],
    "type": ["VerifiableCredential", "ExampleCredential"],
    "id": "did:webvh:example.com:example:my-did:credential:xyz789",
    "issuer": "did:webvh:example.com:example:my-did",
    "issuanceDate": "2024-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:subject",
      "name": "John Doe",
      "age": 30
    },
    "proof": {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-rdfc-2022",
      "created": "2024-01-01T00:00:00Z",
      "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
      "proofPurpose": "assertionMethod",
      "proofValue": "z..."
    }
  },
  "options": {
    "credentialId": "xyz789"
  }
}
```

**Response (201 Created):**
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/data-integrity/v1"
  ],
  "type": ["VerifiableCredential", "ExampleCredential"],
  "id": "did:webvh:example.com:example:my-did:credential:xyz789",
  "issuer": "did:webvh:example.com:example:my-did",
  "issuanceDate": "2024-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "name": "John Doe",
    "age": 30
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2024-01-01T00:00:00Z",
    "verificationMethod": "did:webvh:example.com:example:my-did#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z..."
  }
}
```

### Get Credential

**GET** `/{namespace}/{alias}/credentials/{credential_id}`

Retrieves a specific credential by ID.

**Example Request:**
```http
GET /example/my-did/credentials/xyz789
```

**Response:**
Same structure as upload response.

### Update Credential

**PUT** `/{namespace}/{alias}/credentials/{credential_id}`

Updates an existing credential.

**Request Body:**
Same structure as upload, with updated content and new proof.

**Response:**
Same as upload response (200 OK).

## Invitation Endpoints

### Get Witness Invitation

**GET** `/api/invitations`

Retrieves a witness invitation by witness key (multikey).

**Query Parameters:**

- `_oobid` (required): The witness key (multikey portion of the `did:key` identifier)

**Example Request:**
```http
GET /api/invitations?_oobid=z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

**Response (200 OK):**
```json
{
  "@type": "https://didcomm.org/out-of-band/1.1/invitation",
  "@id": "inv-123",
  "label": "Example Witness Service",
  "goal_code": "witness-service",
  "goal": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "services": [
    {
      "id": "#inline",
      "type": "did-communication",
      "serviceEndpoint": "https://witness.example.com/agent",
      "recipientKeys": ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#recipient"]
    }
  ]
}
```

**Response (404 Not Found):**
```json
{
  "detail": "Invitation not found"
}
```

## Admin Endpoints

All admin endpoints require authentication via `x-api-key` header.

### Get Policy Parameters

**GET** `/api/admin/parameters`

Returns the parameters generated from the active server policy.

**Request:**
```http
GET /api/admin/parameters
x-api-key: your-api-key
```

**Response:**
```json
{
  "version": "1.0",
  "witness": {
    "threshold": 1,
    "witnesses": [
      {
        "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      }
    ]
  },
  "portability": true,
  "prerotation": true,
  "endorsement": true
}
```

### Add Known Witness

**POST** `/api/admin/witnesses`

Adds a witness to the known witness registry.

**Request Body:**
```json
{
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "label": "Example Witness Service",
  "invitationUrl": "https://witness.example.com/oob-invite?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICJpbnYtZXhhbXBsZS0xMjMiLCAibGFiZWwiOiAiRXhhbXBsZSBXaXRuZXNzIFNlcnZpY2UiLCAiZ29hbF9jb2RlIjogIndpdG5lc3Mtc2VydmljZSIsICJnb2FsIjogImRpZDprZXk6ejZNa2hhWGdCWkR2b3REa0w1MjU3ZmFpenRpR2lDMlF0S0xHcGJubkVHdGEyZG9LIiwgInNlcnZpY2VzIjogW3siaWQiOiAiI2lubGluZSIsICJ0eXBlIjogImRpZC1jb21tdW5pY2F0aW9uIiwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwczovL3dpdG5lc3MuZXhhbXBsZS5jb20vYWdlbnQiLCAicmVjaXBpZW50S2V5cyI6IFsiZGlkOmtleTp6Nk1raGFYZ0JaRHZvdERrTDUyNTdmYWl6dGlHaUMyUXRLTEdwYm5uRUd0YTJkb0sjcmVjaXBpZW50Il19XX0="
}
```

**Response (200 OK):**
```json
{
  "registry_id": "knownWitnesses",
  "registry_type": "witnesses",
  "registry": {
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK": {
      "name": "Example Witness Service",
      "serviceEndpoint": "https://example.com/api/invitations?_oobid=z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    }
  },
  "meta": {
    "created": "2024-01-01T00:00:00Z",
    "updated": "2024-01-01T00:00:00Z"
  }
}
```

**Note:** The `label` field is optional. If not provided, it will be extracted from the invitation.

### Remove Known Witness

**DELETE** `/api/admin/witnesses/{multikey}`

Removes a witness from the registry.

**Example Request:**
```http
DELETE /api/admin/witnesses/z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
x-api-key: your-api-key
```

**Response (200 OK):**
```json
{
  "registry_id": "knownWitnesses",
  "registry_type": "witnesses",
  "registry": {},
  "meta": {
    "updated": "2024-01-01T00:00:00Z"
  }
}
```

## Error Responses

All endpoints may return error responses in the following format:

**400 Bad Request:**
```json
{
  "detail": "Invalid request: Policy infraction: Witness signature required"
}
```

**401 Unauthorized:**
```json
{
  "detail": "Invalid or missing API Key"
}
```

**404 Not Found:**
```json
{
  "detail": "DID not found"
}
```

**409 Conflict:**
```json
{
  "detail": "Resource already exists"
}
```

**422 Unprocessable Entity:**
```json
{
  "detail": [
    {
      "loc": ["body", "logEntry"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

## Interactive API Documentation

When the server is running, interactive API documentation is available at:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`
