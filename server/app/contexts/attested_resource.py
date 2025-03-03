
ATTESTED_RESOURCE = {
    "@context": {
        "@protected": True,
        "id": "@id",
        "type": "@type",
        "digestMultibase": {
          "@id": "https://w3id.org/security#digestMultibase",
          "@type": "https://w3id.org/security#multibase"
        },
        "AttestedResource": {
            "@id": "https://www.w3.org/ns/credentials/undefined-term#AttestedResource",
            "@protected": True,
            "@context": {
                "content": {
                  "@id": "https://www.w3.org/ns/credentials/undefined-term#content",
                  "@type": "@id",
                  "@vocab": "vocab"
                },
                "metadata": {
                  "@id": "https://www.w3.org/ns/credentials/undefined-term#metadata",
                  "@type": "@id",
                  "@vocab": "vocab"
                },
                "links": {
                  "@id": "https://www.w3.org/ns/credentials/undefined-term#links",
                  "@type": "@id"
                }
            }
        }
    }
}