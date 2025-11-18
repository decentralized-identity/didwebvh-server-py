# AnonCreds Support

The DID WebVH Server supports publishing and resolving AnonCreds objects as Attested Resources. This enables issuers to publish AnonCreds schemas, credential definitions, revocation registry definitions, and revocation registry states using the DID WebVH method.

## Overview

AnonCreds is a privacy-preserving credential system that provides:
- **Selective Disclosure**: Reveal only specific attributes from a credential
- **Unlinkability**: Multiple presentations cannot be correlated to the same credential
- **Predicate Proofs**: Prove relationships (e.g., age ≥ 18) without revealing exact values
- **Privacy-Preserving Revocation**: Check revocation status without correlation
- **Multi-Credential Presentations**: Combine proofs from multiple credentials

The DID WebVH Server stores AnonCreds objects as `AttestedResource` objects, which are cryptographically signed and linked to the issuer's DID.

## AnonCreds Object Types

Four types of AnonCreds objects can be published on the server:

1. **Schema**: Defines the structure and attributes of a credential type
2. **Credential Definition**: Contains the issuer's public keys for a specific schema
3. **Revocation Registry Definition**: Defines a revocation registry for revocable credentials
4. **Revocation Registry State**: Contains the current state of a revocation registry

Each object is namespaced to the issuer's DID and can be resolved using the DID WebVH resolution protocol.

## Prerequisites

Before publishing AnonCreds objects, you need:

1. **An Issuer DID**: A DID created on the server with a valid `verificationMethod` of type `Multikey`
2. **Witness Connection** (if `WEBVH_ENDORSEMENT=true`): Connection to a witness service for endorsement
3. **Signing Capability**: Ability to create `DataIntegrityProof` signatures using the `eddsa-jcs-2022` cryptosuite

## Creating an AttestedResource

An AnonCreds object is published as an `AttestedResource` with the following structure:

```json
{
  "@context": ["https://w3id.org/security/data-integrity/v2"],
  "id": "did:webvh:{SCID}:example.com:issuer:my-did/resources/{digestMultibase}",
  "content": {
    // AnonCreds object (Schema, Credential Definition, etc.)
  },
  "metadata": {
    "resourceId": "{digestMultibase}",
    "resourceType": "AnonCredsSchema",
    "resourceName": "Example Schema"
  },
  "links": [],
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:webvh:{SCID}:example.com:issuer:my-did#key-1",
    "proofValue": "..."
  }
}
```

### Step-by-Step Process

1. **Initialize the AttestedResource**
   - Create an empty object
   - Set `@context` to `["https://w3id.org/security/data-integrity/v2"]`

2. **Set the Content**
   - Set the `content` property to your AnonCreds object (Schema, Credential Definition, etc.)

3. **Generate the Resource ID**
   - Calculate the `digestMultibase` of the `content` property
   - Construct the resource ID: `{issuer_did}/resources/{digestMultibase}`
   - Example: `did:webvh:abc123:example.com:issuer:my-did/resources/zM6mH...`

4. **Add Metadata** (Optional but Recommended)
   ```json
   {
     "resourceId": "{digestMultibase}",
     "resourceType": "AnonCredsSchema",  // or "AnonCredsCredentialDefinition", etc.
     "resourceName": "Example Schema Name"
   }
   ```

5. **Add Links** (Optional)
   - Add related resource links if the AnonCreds object references other resources
   - Each link should have an `id`, `type`, and optionally `digestMultibase` or `timestamp`

6. **Sign the Resource**
   - Create a `DataIntegrityProof` using `eddsa-jcs-2022` cryptosuite
   - Use a `verificationMethod` from your issuer DID document
   - Set `proofPurpose` to `"assertionMethod"`

7. **Obtain Witness Endorsement** (if `WEBVH_ENDORSEMENT=true`)
   - Request witness signature for the resource
   - Include witness proof alongside your proof in the `proof` array

8. **Upload to Server**
   - **POST** `/{namespace}/{alias}/resources`
   - Include both controller proof and witness proof (if required)

## Uploading AnonCreds Objects

### Example: Uploading a Schema

```bash
# 1. Create the AttestedResource
{
  "@context": ["https://w3id.org/security/data-integrity/v2"],
  "id": "did:webvh:abc123:example.com:issuer:my-did/resources/zM6mH...",
  "content": {
    "name": "Example Schema",
    "version": "1.0",
    "attrNames": ["name", "age", "email"]
  },
  "metadata": {
    "resourceId": "zM6mH...",
    "resourceType": "AnonCredsSchema",
    "resourceName": "Example Schema"
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:webvh:abc123:example.com:issuer:my-did#key-1",
      "proofValue": "..."
    },
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:key:z6Mk...#witness",
      "proofValue": "..."
    }
  ]
}

# 2. Upload to server
curl -X POST "https://did.example.org/issuer/my-did/resources" \
  -H "Content-Type: application/json" \
  -d '{
    "attestedResource": { ... }
  }'
```

### Example: Uploading a Credential Definition

```json
{
  "@context": ["https://w3id.org/security/data-integrity/v2"],
  "id": "did:webvh:abc123:example.com:issuer:my-did/resources/zM6mH...",
  "content": {
    "schemaId": "did:webvh:abc123:example.com:issuer:my-did/resources/zM6mH...",
    "tag": "default",
    "type": "CL",
    "value": {
      "primary": { ... },
      "revocation": { ... }
    }
  },
  "metadata": {
    "resourceId": "zM6mH...",
    "resourceType": "AnonCredsCredentialDefinition",
    "resourceName": "Example Credential Definition"
  },
  "proof": [ ... ]
}
```

## Resolving AnonCreds Objects

AnonCreds objects can be resolved using the DID WebVH resolution protocol:

1. **Get the Resource ID**
   - Example: `did:webvh:abc123:example.com:issuer:my-did/resources/zM6mH...`

2. **Transform DID to HTTPS URL**
   - Extract the DID components: `did:webvh:{SCID}:{domain}:{namespace}:{alias}`
   - Transform to: `https://{domain}/{namespace}/{alias}`
   - Example: `https://example.com/issuer/my-did`

3. **Append Resource Path**
   - Add `/resources/{digestMultibase}` to the URL
   - Example: `https://example.com/issuer/my-did/resources/zM6mH...`

4. **Make GET Request**
   ```bash
   curl https://example.com/issuer/my-did/resources/zM6mH...
   ```

5. **Verify the Resource**
   - Verify the `DataIntegrityProof` signature
   - Calculate `digestMultibase` of `content` and compare with resource ID
   - Verify the `metadata.resourceId` matches (if present)
   - Check that `metadata.resourceType` matches expected type

## Updating AttestedResources

You can update the metadata or links of an existing resource:

1. **Retrieve the Original Resource**
   - GET the resource from the server

2. **Modify Metadata or Links**
   - Update `metadata` properties (e.g., `resourceName`)
   - Add or remove items from `links` array
   - **Note**: The `content` property is immutable

3. **Create New Proof**
   - Generate a new `DataIntegrityProof` with updated timestamp
   - Obtain witness endorsement if required

4. **Update on Server**
   - **PUT** `/{namespace}/{alias}/resources/{resource_id}`
   - Include the updated resource with new proof

```bash
curl -X PUT "https://did.example.org/issuer/my-did/resources/zM6mH..." \
  -H "Content-Type: application/json" \
  -d '{
    "attestedResource": {
      ... // Updated metadata/links with new proof
    }
  }'
```

## Endorsement Requirements

If `WEBVH_ENDORSEMENT=true` (default), resources must be endorsed by a witness:

1. **Controller Signs Resource**
   - Create `DataIntegrityProof` with controller's verification method

2. **Request Witness Endorsement**
   - Send resource to witness service via DIDComm
   - Witness verifies and signs the resource

3. **Include Both Proofs**
   - Controller proof: `verificationMethod` starts with `did:webvh:`
   - Witness proof: `verificationMethod` starts with `did:key:`
   - Both proofs must be in the `proof` array

4. **Server Validation**
   - Server verifies both proofs
   - Server checks witness is in known witness registry
   - Server validates witness key matches registered DID

## Best Practices

1. **Use Descriptive Metadata**
   - Set `resourceType` to clearly identify the AnonCreds object type
   - Use `resourceName` for human-readable identification

2. **Link Related Resources**
   - Use `links` to connect schemas, credential definitions, and revocation registries
   - This enables discovery of related AnonCreds objects

3. **Maintain Resource Immutability**
   - Never modify the `content` property after initial publication
   - Use updates only for metadata and links

4. **Verify Before Use**
   - Always verify `DataIntegrityProof` signatures
   - Check `digestMultibase` matches resource ID
   - Validate witness endorsement if required

5. **Monitor Revocation Registry States**
   - Regularly update revocation registry states
   - Use links to connect states to registry definitions

## API Endpoints

### Upload Resource
- **POST** `/{namespace}/{alias}/resources`
- Uploads a new AnonCreds object as an AttestedResource

### Update Resource
- **PUT** `/{namespace}/{alias}/resources/{resource_id}`
- Updates metadata or links of an existing resource

### Get Resource
- **GET** `/{namespace}/{alias}/resources/{resource_id}`
- Retrieves a specific resource

### List Resources
- **GET** `/{namespace}/{alias}/resources`
- Lists all resources for a DID

## Related Documentation

- [AnonCreds Specification](https://anoncreds.org/)
- [DID Attested Resources](https://identity.foundation/did-attested-resources/)
- [Data Integrity Proofs](https://www.w3.org/TR/vc-data-integrity/)
- [DID WebVH Specification](https://identity.foundation/didwebvh/)





