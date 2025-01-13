#! /bin/bash

DID_REQUEST=$(curl -H Host:server.docker.localhost \
    'http://127.0.0.1?namespace=demo&identifier=issuer' | jq .)

DID_DOCUMENT=$(echo $DID_REQUEST | jq .didDocument)
PROOF_OPTIONS=$(echo $DID_REQUEST | jq .proofOptions)
UPDATE_KEY=$(curl -X 'POST' -H Host:agent.docker.localhost \
  'http://127.0.0.1/wallet/keys' \
  -d '{}' | jq -r .multikey)
CONTROLLER_VERIFICATION_METHOD="did:key:$UPDATE_KEY#$UPDATE_KEY"

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


curl -H Host:server.docker.localhost http://127.0.0.1/demo/issuer/did.json | jq .

LOG_ENTRY=$(curl -H Host:server.docker.localhost http://127.0.0.1/demo/issuer | jq .logEntry)
CONTROLLER_PROOF_OPTIONS=$(jq 'del(.challenge)' <<< "$CONTROLLER_PROOF_OPTIONS")
CONTROLLER_PROOF_OPTIONS=$(jq 'del(.domain)' <<< "$CONTROLLER_PROOF_OPTIONS")
CONTROLLER_PROOF_OPTIONS=$(jq 'del(.expires)' <<< "$CONTROLLER_PROOF_OPTIONS")
PAYLOAD=$(cat <<EOF 
{"document": $LOG_ENTRY, "options": $CONTROLLER_PROOF_OPTIONS}
EOF
)
SIGNED_LOG_ENTRY=$(curl -X 'POST' -H Host:agent.docker.localhost \
  -H 'Content-Type: application/json' \
  'http://127.0.0.1/vc/di/add-proof' \
  -d ''"$PAYLOAD"'' | jq .securedDocument)

PAYLOAD=$(cat <<EOF 
{"logEntry": $SIGNED_LOG_ENTRY}
EOF
)
curl -X 'POST' -H Host:server.docker.localhost \
  -H 'Content-Type: application/json' \
  'http://127.0.0.1/demo/issuer' \
  -d ''"$PAYLOAD"'' | jq .
