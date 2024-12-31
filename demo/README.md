# DID WebVH Server Demo

There's 3 ways to run this demo:
- Using the deployed demo instance of the services through the public Postman workspace.
  - Just head to the [public Postman workspace](https://www.postman.com/bcgov-digital-trust/trust-did-web-server) and follow the instructions.
  - You can also import this workspace by searching for `Trust DID Web Server` in the public API Network.

- Deploying the project locally and using a desktop installation of Postman to execute the requests.
  - You will need a **local** installation of the [Postman desktop app](https://www.postman.com/downloads/). Once you have this, you can import the [public workspace](https://www.postman.com/bcgov-digital-trust/trust-did-web-server). The workspace also contains additional documentation for runnig this demo.

- Deploying the project locally and using the OpenAPI web interfaces of each service.

## Setting up you local deployments

You will need a docker installation, curl, jq and a bash shell.

Once this is all checked, you can clone the repo, move to the demo repository and start the services:
```bash
git clone https://github.com/OpSecId/trustdidweb-server-py.git
cd trustdidweb-server-py/demo/ && ./manage start
    
```

Confirm the services are up and running with the following curl commands
```bash
curl -H Host:server.docker.localhost \
    http://127.0.0.1/server/status | jq .
    
curl -H Host:agent.docker.localhost \
    http://127.0.0.1/status/ready | jq .
    
```

*You can visit the following pages in your browser*
- http://agent.docker.localhost
- http://server.docker.localhost/docs

## Create a DID

Time required: Less than 10 minutes

DID web requires a public endpoint to be globally resolveable. For this demo, we will operate on a local docker network as a proof of concept.

This demo also serves as an introduction to Data Integrity proof sets.

### Request a did namespace and identifier
```bash
namespace='demo'
identifier='issuer'
curl -H Host:server.docker.localhost \
    http://127.0.0.1?namespace=$namespace&identifier=$identifier | jq .
```
```json
{
  "document": {
    "@context": [
      "https://www.w3.org/ns/did/v1"
    ],
    "id": "did:web:server.docker.localhost:demo:issuer"
  },
  "options": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "authentication",
    "created": "2024-09-06T20:57:52+00:00",
    "expires": "2024-09-06T21:07:52+00:00",
    "domain": "server.docker.localhost",
    "challenge": "de96aa5e-3c6d-55d7-9ef7-77dd98cabf96"
  }
}
```
From this point on, you have 10 minutes to complete the rest of this demo before the proof configuration is expired. You can restart at any moment with the `./manage restart` command.

## Create a new verification Method
Open the browser and register a new verification method with the agent.
- http://issuer.docker.localhost/api/doc#/wallet/post_keys

Here's a sample request you can copy into the OpenAPI interface.

```json
{
    "kid": "did:web:server.docker.localhost:demo:issuer#key-01"
}
```

## Create and sign the did document
Create your DID document, adding the verification method created at the previous step. Also add an `authentication` and `assertionMethod` relationship to this verification method.
```json
{
    "@context": [
      "https://www.w3.org/ns/did/v1"
    ],
    "id": "did:web:server.docker.localhost:demo:issuer",
    "authentication": ["did:web:server.docker.localhost:demo:issuer#key-01"],
    "assertionMethod": ["did:web:server.docker.localhost:demo:issuer#key-01"],
    "verificationMethod": [
        {
            "id": "did:web:server.docker.localhost:demo:issuer#key-01",
            "type": "MultiKey",
            "controller": "did:web:server.docker.localhost:demo:issuer",
            "publicKeyMultibase": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i"
        }
    ],
}
```
Sign with the proof options obtained from step 1.
- http://issuer.docker.localhost/api/doc#/wallet/post_wallet_di_add_proof

See below for a template to use as your request body.
- *You will need to use the options you obtained since there's an expiration of 10 minutes and a unique challenge was created.*
- *Also, you will need to add the verificationMethod you created.*
```json
{
  "document": {
        "@context": [
          "https://www.w3.org/ns/did/v1"
        ],
        "id": "did:web:server.docker.localhost:demo:issuer",
        "authentication": ["did:web:server.docker.localhost:demo:issuer#key-01"],
        "assertionMethod": ["did:web:server.docker.localhost:demo:issuer#key-01"],
        "verificationMethod": [
            {
                "id": "did:web:server.docker.localhost:demo:issuer#key-01",
                "type": "MultiKey",
                "controller": "did:web:server.docker.localhost:demo:issuer",
                "publicKeyMultibase": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i"
            }
        ]
    },
  "options": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "authentication",
    "created": "⚠️",
    "expires": "⚠️",
    "domain": "server.docker.localhost",
    "challenge": "⚠️",
    "verificationMethod": "did:key:⚠️#⚠️"
  }
}

```

## Request an endorser signature
Request an endorser signature on the signed did document.
- http://endorser.docker.localhost/api/doc#/wallet/post_wallet_di_add_proof

See below for a template to use as your request body.
- *Again, you will need to use the options you obtained since there's an expiration of 10 minutes and a unique challenge was created.*
- *Also, you will need to add the `verificationMethod` from the endorser, which is derived from the server's root did: `did:web:server.docker.localhost#key-01`. This has been provisioned on the endorser agent during startup.*
```json
{
  "document": {
        "@context": [
          "https://www.w3.org/ns/did/v1"
        ],
        "id": "did:web:server.docker.localhost:demo:issuer",
        "authentication": ["did:web:server.docker.localhost:demo:issuer#key-01"],
        "assertionMethod": ["did:web:server.docker.localhost:demo:issuer#key-01"],
        "verificationMethod": [
            {
                "id": "did:web:server.docker.localhost:demo:issuer#key-01",
                "type": "MultiKey",
                "controller": "did:web:server.docker.localhost:demo:issuer",
                "publicKeyMultibase": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i"
            }
        ],
        "proof": [
          {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "authentication",
            "verificationMethod": "did:key:⚠️#⚠️",
            "created": "⚠️",
            "expires": "⚠️",
            "domain": "server.docker.localhost",
            "challenge": "⚠️",
            "proofValue": "z3GBx56nXZDead55EXi85tLyeXiS2oTa3SEkQYtgiqGANE6k4GxZXFNs1Uh7tdAA2tsgo8HarkZs8YrCwuA8biQaj"
          }
        ]
    },
  "options": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "authentication",
    "verificationMethod": "did:key:z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i#z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i ",
    "created": "⚠️",
    "expires": "⚠️",
    "domain": "server.docker.localhost",
    "challenge": "⚠️"
  }
}
```

## Send the request back to the server
Now that we have a DID document with a proof set, we can send this back to the did web server to finalize the did registration.
- http://server.docker.localhost/docs#/Identifiers/register_did__namespace___identifier__post

If you completed the steps properly and within 10 minutes, your DID will now be available.

If you get an error, try restarting the demo using the `./manage restart` command.


## Resolve (locally) your new DID
```bash
curl -H Host:server.docker.localhost http://127.0.0.1/demo/issuer/did.json | jq .
```
