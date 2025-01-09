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
git clone https://github.com/identity-foundation/didwebvh-server-py.git
cd didwebvh-server-py/demo/ && ./manage start
    
```

Confirm the services are up and running with the following curl commands
```bash
curl -H Host:server.docker.localhost \
    http://127.0.0.1/server/status | jq .
    
curl -H Host:agent.docker.localhost \
    http://127.0.0.1/status/ready | jq .
    
```

*You can visit the following pages in your browser*
- http://agent.docker.localhost/api/doc
- http://server.docker.localhost/docs

## Create a DID

Time required: Less than 10 minutes

DID web requires a public endpoint to be globally resolveable. For this demo, we will operate on a local docker network as a proof of concept.

This demo also serves as an introduction to Data Integrity proof sets.

At any time, you can reset this demo with the `./manage restart` command.

### Request a did namespace and identifier
```bash
DID_REQUEST=$(curl -H Host:server.docker.localhost \
    'http://127.0.0.1?namespace=demo&identifier=issuer' | jq .)

DID_DOCUMENT=$(echo $DID_REQUEST | jq .didDocument)
PROOF_OPTIONS=$(echo $DID_REQUEST | jq .proofOptions)

```

The proof options generated have a 10 minutes validity period, after which you will need to request a new set of options.

## Create an update key for this did
```bash
# http://agent.docker.localhost/api/doc#/wallet/post_wallet_keys

UPDATE_KEY=$(curl -X 'POST' -H Host:agent.docker.localhost \
  'http://127.0.0.1/wallet/keys' \
  -d '{}' | jq -r .multikey)
CONTROLLER_VERIFICATION_METHOD="did:key:$UPDATE_KEY#$UPDATE_KEY"

```

## Sign the did document
You can optionally add information to your did document containing the content you want to publish. Refer to the did core spec to get familiar with such features. For this demo, we will leave it as is.

Sign with the proof options obtained from step 1.
```bash
# http://issuer.docker.localhost/api/doc#/wallet/post_wallet_di_add_proof

# Add verificationMethod to the proof options
CONTROLLER_PROOF_OPTIONS=$(jq '. += {"verificationMethod": "'"$CONTROLLER_VERIFICATION_METHOD"'"}' <<< "$PROOF_OPTIONS")

# Construct the payload for the request
PAYLOAD=$(cat <<EOF 
{"document": $DID_DOCUMENT, "options": $CONTROLLER_PROOF_OPTIONS}
EOF
)

# Request a signature on the did document
SIGNED_DID_DOC=$(curl -X 'POST' -H Host:agent.docker.localhost \
  -H 'Content-Type: application/json' \
  'http://127.0.0.1/vc/di/add-proof' \
  -d ''"$PAYLOAD"'' | jq .securedDocument)

```

## Request an endorser signature
Request an endorser signature on the signed did document.

```bash
# http://issuer.docker.localhost/api/doc#/wallet/post_wallet_di_add_proof

# Change verificationMethod to the proof options
ENDORSER_KEY='z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i'
ENDORSER_VERIFICATION_METHOD="did:key:$ENDORSER_KEY#$ENDORSER_KEY"
ENDORSER_PROOF_OPTIONS=$(jq '. += {"verificationMethod": "'"$ENDORSER_VERIFICATION_METHOD"'"}' <<< "$PROOF_OPTIONS")

# Construct the payload for the request
PAYLOAD=$(cat <<EOF 
{"document": $SIGNED_DID_DOC, "options": $ENDORSER_PROOF_OPTIONS}
EOF
)

# Request a signature on the did document
ENDORSED_DID_DOC=$(curl -X 'POST' -H Host:agent.docker.localhost \
  -H 'Content-Type: application/json' \
  'http://127.0.0.1/vc/di/add-proof' \
  -d ''"$PAYLOAD"'' | jq .securedDocument)

```

## Send the request back to the server
Now that we have a DID document with a proof set, we can send this back to the did web server to finalize the did registration.
- http://server.docker.localhost/docs#/Identifiers/register_did__namespace___identifier__post

If you completed the steps properly and within 10 minutes, your DID will now be available.

If you get an error, try restarting the demo using the `./manage restart` command.

```bash
# Construct the payload for the request
PAYLOAD=$(cat <<EOF 
{"didDocument": $ENDORSED_DID_DOC}
EOF
)

# Request a signature on the did document
curl -X 'POST' -H Host:server.docker.localhost \
  -H 'Content-Type: application/json' \
  'http://127.0.0.1/' \
  -d ''"$PAYLOAD"'' | jq .

```

## Resolve (locally) your new DID
```bash
curl -H Host:server.docker.localhost http://127.0.0.1/demo/issuer/did.json | jq .
```

## Initialise the DID Log

```bash
LOG_ENTRY=$(curl -H Host:server.docker.localhost http://127.0.0.1/demo/issuer | jq .logEntry)
PAYLOAD=$(cat <<EOF 
{"document": $LOG_ENTRY, "options": $CONTROLLER_PROOF_OPTIONS}
EOF
)
```