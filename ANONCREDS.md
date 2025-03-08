# AnonCreds with WebVH

## Summary

The WebVH server enables a controller to upload resources as `AttestedResource` objects. This is the format AnonCreds object will leverage for WebVH.

## AnonCreds object types

For more detail please refer to the AnonCreds specification.

4 AnonCreds object types can be uploaded to the server

- Schema
- Credential Definition
- Revocation Registry Definition
- Revocation Registry State

Each object will be namespaced to the issuer of the resource.

## Uploading a resource

To upload a resource, you will need an existing DID with a valid `verificationMethod` of type `Multikey`.

The data model for resources is as follows:
```json
{
    "@context": [],
    "id": "",
    "content": {},
    "metadata": {},
    "links": [],
    "proof": {}
}
```

This resource MUST be signed with a `DataIntegrityProof` using the `eddsa-jcs-2022` cryptosuite, then sent as a POST request to the `/resources` endpoint.

### Creating an AttestedResource
- Initiate an empty object as the `AttestedResource`.
- Set the `@context` property to `["https://w3id.org/security/data-integrity/v2"]`
- Set the `content` property to the json object you wish to publish, such as an AnonCreds Schema.
- Generate the `AttestedResource` `id`:
    - Calculate the `digestMultibase` of the `content` property.
    - Add a `/resources` path to the issuer's did then join the `digestMultibase` from the previous step as the resource identifier.
        - ex: `did:webvh:{SCID}:example.com:{namespace}:{identifier}/resources/{digestMultibase}`
    - Set the `id` property of the `AttestedResource` to this value.
- (Optional) Generate the `AttestedResource` `metadata`:
    - Set the `metadata` property to an empty object:
    - Add a `resourceId` property, and set it to the `digestMultibase` value calculated previously.
    - Add a `resourceType` property, and set it to a type representing the `content`, such as `AnonCredsSchema`.
    - Add a `resourceName` property, and set it to a string value representing the `content`, such as the schema name or a tag.
        - Refer to the DID linked resource spec for other metadata elements as desired.
- (Optional) Add related links:
    - Set the `links` property of the `AttestedResource` to an empty list
    - Add related links objects, consisting of an `id`, a `type` and optionally, a `digestMultibase` or a `timestamp`.
- Add a `DataIntegrityProof` to the `AttestedResource` using the `eddsa-jcs-2022` cryptosuite and a `verificationMethod` from the issuer's did document.
- POST this to the `/resources` endpoint of the DID WebVH server.


### Updating an AttestedResource
- Edit the `metadata` or the `links` from the original `AttestedResource`
- Create a new `DataIntegrityProof` and replace the existing one
- PUT this to the existing location of this file on the DID WebVH server.


### Resolving an AttestedResource
- Get the `id` of the `AttestedResource`
    - ex: `did:webvh:{SCID}:example.com:{namespace}:{identifier}/resources/{digestMultibase}`
- Dereference the `id` into a document:
    - Transform the did portion of the uri into a https url.
        - `did:webvh:{SCID}:example.com:{namespace}:{identifier}` -> `https://example.com/{namespace}/{identifier}`
    - Append the path portions of the uri.
        - `https://example.com/{namespace}/{identifier}` -> `https://example.com/{namespace}/{identifier}/resources/{digestMultibase}`
    - Make a GET request
- Verify the integrity of the `AttestedResource`
    - Verify the`DataIntegrityProof`
- Verify the immutability of the `content`
    - Calculate a `digestMultibase` from the `content` of the `AttestedResource`
    - Compare with the left-most portion of the URI and optionally the `metadata.resourceId` value. These MUST match.
- (Optional) Ensure the `metadata.resourceType` is expected based on the context.
- Read the `content`