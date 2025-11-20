# Configuration

## Environment Variables

Create a `.env` file in the `server` directory with the following variables:

### Base Configuration

- `WEBVH_DOMAIN`: Your server domain (e.g., `did.example.org`)
- `WEBVH_ADMIN_API_KEY`: API key for admin endpoints (e.g., `change-me`)

### Witness Configuration

- `WEBVH_WITNESS_ID`: Full `did:key` identifier for the server's witness (e.g., `did:key:z6Mk...`)
- `WEBVH_WITNESS_INVITATION`: Full invitation URL with `?oob=` parameter for the witness

### Policy Configuration

- `WEBVH_VERSION`: WebVH method version to enforce (default: `1.0`)
- `WEBVH_WITNESS`: Require witness signatures (default: `true`)
- `WEBVH_WATCHER`: Optional watcher URL to enforce
- `WEBVH_PORTABILITY`: Require portability (default: `true`)
- `WEBVH_PREROTATION`: Require prerotation (default: `true`)
- `WEBVH_ENDORSEMENT`: Require witness endorsement for resources (default: `true`)

## Policy Application

The server automatically applies policy settings from environment variables on startup. Any changes to environment variables will be reflected after a server restart.





