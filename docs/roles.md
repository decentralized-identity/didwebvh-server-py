# Roles

The DID WebVH Server architecture involves four distinct roles, each with specific responsibilities and capabilities. Understanding these roles is essential for deploying and operating a DID WebVH server.

## Admin

The **Admin** role manages the server configuration, policies, and witness registry. Admins have full administrative control over the server.

### Responsibilities

- **Server Policy Management**: Configure and update server policies including:
    - Witness requirements (`WEBVH_WITNESS`)
    - Watcher URLs (`WEBVH_WATCHER`)
    - Portability settings (`WEBVH_PORTABILITY`)
    - Prerotation requirements (`WEBVH_PREROTATION`)
    - Endorsement requirements (`WEBVH_ENDORSEMENT`)
    - WebVH method version (`WEBVH_VERSION`)

- **Witness Registry Management**: 
    - Add known witnesses to the registry
    - Remove witnesses from the registry
    - Update witness invitation URLs
    - View the current witness registry

- **Server Monitoring**: 
    - View server status and health
    - Monitor DID operations
    - Access administrative endpoints

### Authentication

Admins authenticate using the `WEBVH_ADMIN_API_KEY` environment variable. This API key must be provided in the `x-api-key` HTTP header when accessing admin endpoints.

### API Endpoints

- `POST /api/admin/witnesses` - Add a known witness
- `DELETE /api/admin/witnesses/{witness_id}` - Remove a witness
- `GET /api/admin/parameters` - Get current policy parameters
- `GET /api/server/status` - Get server status

### Example

```bash
# Add a witness
curl -X POST "https://did.example.org/api/admin/witnesses" \
  -H "x-api-key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "label": "Example Witness Service",
    "invitationUrl": "https://witness.example.com/oob-invite?oob=..."
  }'
```

## Witness

The **Witness** role provides attestation and signing services for DID operations. Witnesses must be registered in the server's known witness registry before they can sign DID registrations and updates.

### Responsibilities

- **DID Attestation**: Sign DID registration requests from controllers
- **DID Update Verification**: Sign DID update requests when required by policy
- **Resource Endorsement**: Endorse attested resources when server policy requires endorsement (`WEBVH_ENDORSEMENT=true`)
- **Credential Endorsement**: Endorse verifiable credentials issued by controllers
- **Connection Management**: Maintain DIDComm connections with controllers
- **Service Advertisement**: Advertise invitation URLs through the server's DID document

### Registration

Witnesses must be registered by an Admin before they can provide services:

1. Admin adds the witness to the known witness registry with:
    - Witness DID (`did:key:...`)
    - Witness label/name
    - Full invitation URL (with `?oob=` parameter)

2. The server:
    - Stores the witness invitation
    - Adds the witness to the server's DID document as a `WitnessInvitation` service
    - Makes the witness available for controllers to discover and connect

### Witness Keys

Witnesses use `did:key` identifiers with Ed25519 multikey format. The witness key must be registered in the server's known witness registry for signatures to be accepted.

### Service Discovery

Controllers discover witnesses through the server's DID document:

```bash
# Get server DID document
curl https://did.example.org/.well-known/did.json

# Response includes witness services:
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
```

### Signature Requirements

When server policy requires witnesses (`WEBVH_WITNESS=true`), controllers must obtain witness signatures for:
    - Initial DID registration
    - DID updates (if policy requires ongoing witness attestation)

Witness signatures are included in the `witnessSignature` field of log entry requests.

### Endorsement Requirements

When server policy requires endorsement (`WEBVH_ENDORSEMENT=true`), witnesses must endorse:
    - **Attested Resources**: Controllers submit resources with witness proofs. The witness verifies and signs the resource, providing an endorsement proof that must be included when uploading to the server.
    - **Verifiable Credentials**: Controllers issue credentials that require witness endorsement. Witnesses verify and sign credentials, providing endorsement proofs.

Endorsement proofs are included alongside controller proofs in resource and credential upload requests. The server validates that:
    - The witness is registered in the known witness registry
    - The witness proof is cryptographically valid
    - The witness key matches a registered witness DID

## Controller

The **Controller** role owns and manages DIDs. Controllers create, update, and deactivate DIDs through the server.

### Responsibilities

- **DID Creation**: Request DID paths and create new DIDs
- **DID Updates**: Submit log entries to update DID documents
- **DID Deactivation**: Deactivate DIDs when no longer needed
- **Witness Signature Management**: Request and collect witness signatures for DID operations, resources, and credentials
- **Watcher Notification**: Notify watcher services of DID operations when watchers are configured
- **Resource Management**: Create and manage attested resources bound to DIDs
- **Credential Management**: Issue and manage verifiable credentials

### DID Lifecycle

1. **Request DID Path**
    - Controller requests a DID path: `GET /?namespace={namespace}&alias={alias}`
    - Server returns policy-driven parameters

2. **Create Initial Log Entry**
    - Controller constructs the initial log entry
    - Controller signs the log entry with their update key
    - If policy requires witnesses, controller requests witness signatures

3. **Submit Log Entry**
    - Controller submits the log entry: `POST /{namespace}/{alias}`
    - Server validates and publishes the DID

4. **Update DID**
    - Controller submits subsequent log entries to update the DID
    - Each update must be signed with the controller's update key
    - Witness signatures may be required depending on policy

### Update Keys

Controllers use update keys to sign log entries. The initial update key is specified in the first log entry and must be used for all subsequent updates.

### Watcher Notification

When watchers are configured (`WEBVH_WATCHER` is set), controllers are responsible for notifying watcher services of DID operations:

1. **Include Watcher in Parameters**: Controllers must include watcher URLs in DID parameters as specified by server policy
2. **Notify on Operations**: Controllers notify watchers when:
    - Creating new DIDs
    - Updating existing DIDs
    - Publishing resources or credentials (if watcher monitoring is required)

Watcher notification ensures that monitoring services can observe and audit DID operations for compliance purposes.

### Witness Interaction

Controllers are responsible for requesting and collecting witness signatures. When server policy requires witnesses:

1. **Connect to Witness**: Controller connects to witness service using invitation from server DID document
2. **Request Signatures**: Controller requests witness signatures for:
    - DID log entries (registration and updates)
    - Attested resources (when `WEBVH_ENDORSEMENT=true`)
    - Verifiable credentials (when `WEBVH_ENDORSEMENT=true`)
3. **Collect Signatures**: Controller collects witness signatures and proofs
4. **Include in Submissions**: Controller includes witness signatures when submitting to server

The controller must coordinate with witnesses to obtain all required signatures before submitting operations to the server.

### Example

```bash
# 1. Request DID path
curl "https://did.example.org/?namespace=example&alias=my-did"

# 2. Create and sign log entry (with witness signature if required)
# 3. Submit log entry
curl -X POST "https://did.example.org/example/my-did" \
  -H "Content-Type: application/json" \
  -d '{
    "logEntry": {...},
    "witnessSignature": {...}
  }'
```

## Watcher

The **Watcher** role is an optional monitoring service that can observe DID operations. Watchers are configured at the server policy level and are included in DID parameters.

### Responsibilities

- **DID Monitoring**: Observe DID creation and updates
- **Audit Trail**: Maintain records of DID operations
- **Compliance**: Verify DID operations comply with policies

### Configuration

Watchers are configured via the `WEBVH_WATCHER` environment variable:

```bash
WEBVH_WATCHER=https://watcher.example.com
```

When configured, the watcher URL is included in all DID parameters:

```json
{
  "parameters": {
    "method": "did:webvh:1.0",
    "watchers": ["https://watcher.example.com"],
    ...
  }
}
```

### Policy Enforcement

If a watcher is configured:
    - All DID parameters must include the watcher URL
    - Controllers must include the watcher in their DID configuration
    - The server validates that watchers match policy requirements

### Optional Role

Watchers are optional. If `WEBVH_WATCHER` is not set, the `watchers` array in DID parameters will be empty or omitted.

## Role Interactions

### Admin ↔ Witness

- Admin registers witnesses in the known witness registry
- Admin can remove witnesses from the registry
- Witnesses advertise their services through the server (managed by Admin)

### Controller ↔ Witness

- Controller discovers witnesses through server DID document
- Controller connects to witness via DIDComm invitation
- Controller requests and collects witness signatures for:
    - DID log entries (registration and updates)
    - Attested resources (when endorsement required)
    - Verifiable credentials (when endorsement required)
- Witness verifies and signs controller requests
- Controller coordinates with witnesses to obtain all required signatures

### Controller ↔ Server

- Controller requests DID paths from server
- Controller submits log entries to server
- Server validates controller requests and enforces policies
- Server publishes DID documents and logs

### Controller ↔ Watcher

- Controller notifies watcher services of DID operations
- Controller includes watcher URLs in DID parameters (if configured)
- Controller notifies watchers when creating or updating DIDs
- Watcher observes and audits DID operations for compliance

## Summary

| Role | Primary Function | Authentication | Required |
|------|-----------------|----------------|----------|
| **Admin** | Server and policy management | API Key | Yes (for server operation) |
| **Witness** | DID attestation and signing | DID Key | Yes (if `WEBVH_WITNESS=true`) |
| **Controller** | DID creation and management | Update Keys | Yes (for DID operations) |
| **Watcher** | DID monitoring and audit | N/A | No (optional) |

Each role plays a specific part in the DID WebVH ecosystem, ensuring secure, verifiable, and auditable DID operations.

