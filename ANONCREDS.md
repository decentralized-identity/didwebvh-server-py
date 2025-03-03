# AnonCreds Objects (AttestedResources)

## Attested Resource
An attested resource is a secured blob of content published with identifying metadata.

The key security features of an attested resource are:
Data Integrity: The object is signed with a Data Integrity Proof
Data immutability: The content of the object is cryptographically bound to it's location identifier through a digest.

There are 5 elements in an attested resource:
- id: The identifier of the resource. This is a URI which is dereferenceable to the location of the attested resource. The last (left most) path components of this value is a digestMultibase of the `content` property of the attested resource.
- content: The immutable content of the resource as a json object. This is typically a piece of content that will be used by the consumer and the key resource data.
- metadata: key/value pairs of metadata elements, matching the DIDLinkedResource metadata specification.
- relatedLinks: A list of objects containing an `id` and a `type`, and optionally a `digestMultibase` and/or `timestamp`.
- proof: A Data Integrity Proof, using the eddsa-jcs-2022 cryptosuite.

## AnonCreds Objects
To enable AnonCreds with WebVH, 4 distinct objects are posted as AttestedResources
- Schema
- Credential Definition
- Revocation Registry
- Revocation List Entry

The Revocation Registry will have a link to every published Revocation List Entry in the `relatedLinks` property of the `AttestedResource`