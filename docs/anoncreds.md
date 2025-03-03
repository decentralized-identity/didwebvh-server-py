# AnonCreds with WebVH

## Summary

We can leverage the implicit fileserver service of webVH to link to and resolve AnonCreds object.

## Object types

For more detail please refer to the AnonCreds specification.

3 AnonCreds object types can be uploaded to the server

- Schema
- Credential Definition
- Revocation Registry Definition

Each object will be namespaced to the issuer of the resource.

## AnonCreds routes

POST /anoncreds/schemas
POST /anoncreds/definitions
POST /anoncreds/registries

## Uploading a ressource

Typically, you will start by uploading a schema, unless you are leveraging an already published schema. To upload the resource, you will need an exiting DID with a valid multikey type verificationMethod.

Once the schema object is created, sign it using the configured parameters:
```
```

To generate a valid schema, use a conformant anoncreds implementation.

Send a post request to the schema upload endpoint using the signed object as the payload.