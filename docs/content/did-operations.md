# DID Operations

## Creating a DID

1. **Request Parameters**:
   ```bash
   GET /?namespace=example&alias=my-did
   ```

2. **Response** includes:
   - `parameters`: Policy-driven configuration
   - `state.id`: Placeholder DID identifier
   - `proof`: Proof options

3. **Create Log Entry**:
   - Build a log entry matching the returned parameters
   - Sign it with your controller key
   - Get witness signatures if required

4. **Submit Log Entry**:
   ```bash
   POST /example/my-did
   {
     "logEntry": { ... },
     "witnessSignature": { ... }
   }
   ```

## Updating a DID

Submit a new log entry to the same endpoint:

```bash
POST /example/my-did
{
  "logEntry": { ... },
  "witnessSignature": { ... }
}
```

## Resolving a DID

- **Current State**: `GET /example/my-did/did.json`
- **History**: `GET /example/my-did/did.jsonl`
- **Witness Proofs**: `GET /example/my-did/did-witness.json`

