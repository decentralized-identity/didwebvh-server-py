# Admin Operations

Admin endpoints require API key authentication via the `x-api-key` header.

## Witness Management

### Add Witness

- **POST** `/admin/witnesses`
  - **Headers**: `x-api-key: <WEBVH_ADMIN_API_KEY>`
  - **Body**:
    ```json
    {
      "id": "did:key:z6Mk...",
      "label": "Example Witness Service",
      "invitationUrl": "https://witness.example.com/oob-invite?oob=<base64_encoded_invitation>"
    }
    ```
  - Decodes the invitation, stores it, and creates a short URL in the registry

### Remove Witness

- **DELETE** `/admin/witnesses/{multikey}`
  - **Headers**: `x-api-key: <WEBVH_ADMIN_API_KEY>`
  - Removes a witness from the registry

## Policy Management

### Get Parameters

- **GET** `/admin/parameters`
  - **Headers**: `x-api-key: <WEBVH_ADMIN_API_KEY>`
  - Returns the parameters generated from the active policy
  - Includes witness configuration, method version, and other policy-driven settings

## Witness Management

### Automatic Registration

If both `WEBVH_WITNESS_ID` and `WEBVH_WITNESS_INVITATION` are set, the server will automatically:

1. Decode the invitation from the URL
2. Store the invitation using the witness DID as the key
3. Update the witness registry with a short URL (`https://{DOMAIN}?_oobid={witness_key}`)
4. Update the invitation if it changes on restart

### Invitation Lookup

Witness invitations can be retrieved via the root endpoint:

- **GET** `/?_oobid={witness_key}`
  - Returns the stored invitation as JSON
  - The `witness_key` is the multikey portion of the `did:key` identifier

### Short URLs

The server generates short URLs for witness invitations in the format:
```
https://{DOMAIN}?_oobid={witness_key}
```

These URLs are:
- Stored in the witness registry as `serviceEndpoint`
- Included in the server's DID document under `WitnessInvitation` services
- Resolvable via the root endpoint to return the full invitation JSON





