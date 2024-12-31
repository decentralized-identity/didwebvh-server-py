# DID Web with Verifiable History Server Python
## A Web Server component for a DID WebVH implementation

This server is built with the FastAPI framework.

The DID WebVH spec: [https://identity.foundation/didwebvh](https://identity.foundation/didwebvh)

## Abstract

This server is for issuing clients to deposit their did documents, did logs and other objects.

Having a seperate server to deposit verification material will ensure that signing material is isolated and provide a more secured architecture.

This also enables system architects to create rigid governance rules around publishing DID documents and related ressources through endorsment.

## How it works
*For a demonstration, please see the demo directory*

- An issuer requests an identifier location from the server.
    - The server returns a configuration if the location is available.
- The issuer generates a verification method and signs a did document with it.
    - Using the provided proof configuration from the server.
- The issuer request an endorser signature.
    - Using the provided proof configuration from the server.
- The issuer sends this request back to the server.

### Registering a new DID
```mermaid
sequenceDiagram
    participant Trust DID Web Server
    participant Issuer Client
    participant Endorser Agent
    Issuer Client->>Trust DID Web Server: Request an identifier namespace.
    Trust DID Web Server->>Issuer Client: Provide a DID document and a proof configuration.
    Issuer Client->>Issuer Client: Create new verification method.
    Issuer Client->>Issuer Client: Sign DID document.
    Issuer Client->>Endorser Agent: Request endorser signature.
    Endorser Agent->>Endorser Agent: Verify and sign DID document.
    Endorser Agent->>Issuer Client: Return endorsed DID document.
    Issuer Client->>Trust DID Web Server: Send endorsed DID document.
    Trust DID Web Server->>Trust DID Web Server: Verify endorsed DID document.
```

## Roadmap
- DID log support
- whois VP support
- AnonCreds objects support
- Status lists support
