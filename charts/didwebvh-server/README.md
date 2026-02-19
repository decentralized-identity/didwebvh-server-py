# didwebvh-server-py Helm Chart

Helm chart for the DID Web with Verifiable History server (Python/FastAPI). Deploys the server and optionally a PostgreSQL database (CloudPirates Postgres, official `postgres` image).

## Prerequisites

- Kubernetes 1.24+
- Helm 3.2+
- PV provisioner (if using bundled Postgres with persistence)

## Install

```bash
helm install my-release ./charts/didwebvh-server -f my-values.yaml
```

## Configuration

Key values (see `values.yaml`):

| Parameter | Description | Default |
| --------- | ----------- | ------- |
| `nameOverride` / `fullnameOverride` | Override chart/release names | `didwebvh-server` |
| `server.image.repository` / `server.image.tag` | Server image | `ghcr.io/decentralized-identity/didwebvh-server-py:0.5.0` |
| `server.host` | Public host for the server | `example.com` |
| `server.policies.*` | WebVH policies (witness, endorsement, etc.) | see values.yaml |
| `postgres.enabled` | Deploy Postgres subchart | `true` |
| `postgres.auth.username` / `postgres.auth.database` | DB user and database name | `didwebvh-server` |
| `postgres.persistence.size` | PVC size for Postgres data | `1Gi` |

## Breaking change: Bitnami → CloudPirates Postgres (v0.6.0)

As of chart version **0.6.0**, the Bitnami PostgreSQL subchart has been replaced with the **CloudPirates Postgres** chart, which uses the official Docker `postgres` image.

- **Values:** All `postgresql.*` keys are replaced by `postgres.*`. If you override(d) Bitnami values, update them to the [CloudPirates Postgres](https://artifacthub.io/packages/helm/cloudpirates-postgres/postgres) schema (e.g. `postgres.auth.username`, `postgres.service.port`, `postgres.persistence`, `postgres.config.postgresql`).
- **Secrets:** The Postgres secret is now created by the CloudPirates subchart with key `postgres-password` (no longer `database-password` or `password` from Bitnami).
- **Image:** Container image changes from `bitnami/postgresql` to official `postgres` (e.g. 18.x).

### Upgrade / migration for existing installations

If you are upgrading from a release that used the **Bitnami** PostgreSQL chart, data is **not** migrated automatically. You must back up and restore:

1. **Back up** the existing database (e.g. from the old release):
   ```bash
   kubectl exec -it <old-postgres-pod> -- pg_dump -U didwebvh-server didwebvh-server > backup.sql
   ```
2. **Uninstall** the old release or **upgrade** and let the new Postgres start empty (new PVC or new chart).
3. **Restore** into the new Postgres pod:
   ```bash
   kubectl exec -i <new-postgres-pod> -- psql -U didwebvh-server -d didwebvh-server < backup.sql
   ```

**Fresh installs** do not require any migration.

## Testing the chart

You can test without a cluster:

```bash
cd charts/didwebvh-server

# Lint
helm lint .

# Render manifests (sanity check)
helm template test . --namespace test-ns

# Simulate install (needs a valid kubeconfig)
helm install test . --namespace test-ns --dry-run --debug
```

To test with a real install, use a local cluster (e.g. [kind](https://kind.sigs.k8s.io/) or minikube), then:

```bash
kubectl create namespace test-ns
helm install test . --namespace test-ns --wait
# Check pods: kubectl get pods -n test-ns
# Uninstall: helm uninstall test -n test-ns
```

## License

Apache-2.0
