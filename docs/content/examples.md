# Examples

## Example: Adding a Witness via Admin API

```bash
curl -X POST "https://did.example.org/admin/witnesses" \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "label": "Example Witness Service",
    "invitationUrl": "https://witness.example.com/oob-invite?oob=eyJAdHlwZSI6..."
  }'
```

## Example: Retrieving Invitation

```bash
curl "https://did.example.org?_oobid=z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
```

## Example: Getting Server Parameters

```bash
curl -X GET "https://did.example.org/admin/parameters" \
  -H "x-api-key: your-api-key"
```

## Additional Resources

- **API Documentation**: Available at `/docs` when the server is running
- **Explorer UI**: Available at `/explorer` for browsing DIDs and resources
- **DID WebVH Specification**: [https://identity.foundation/didwebvh](https://identity.foundation/didwebvh)

