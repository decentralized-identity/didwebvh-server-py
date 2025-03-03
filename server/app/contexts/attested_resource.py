
ATTESTED_RESOURCE = {
    "@context": {
        "@protected": True,
        "id": "@id",
        "type": "@type",
        "vocab": "https://#",
        "digestMultibase": {
          "@id": "https://w3id.org/security#digestMultibase",
          "@type": "https://w3id.org/security#multibase"
        },
        "mirrorLink": {
          "@id": "vocab:mirrorLink",
          "@type": "@id"
        },
        "AttestedResource": {
            "@id": "vocab:AttestedResource",
            "@protected": True,
            "@context": {
                "resourceContent": {
                  "@id": "https:///#resourceContent",
                  "@type": "@id",
                  "@vocab": "vocab"
                },
                "resourceMetadata": {
                  "@id": "https://w3c-ccg.github.io/DID-Linked-Resources/#resourcemetadata",
                  "@type": "@id",
                  "@vocab": "vocab"
                },
                "relatedResource": {
                  "@id": "https://www.w3.org/2018/credentials#relatedResource",
                  "@type": "@id"
                }
            }
        }
    }
}