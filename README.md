# authSDK
This AuthSDK functions as a SDK that supports integration with multiple services.

## GitHub CI/CD

### Workflows

- `CI` (`.github/workflows/ci.yml`)
  - Runs on pull requests and pushes to `main`.
  - Executes:
    - `ruff` lint
    - `black --check`
    - `pytest`
    - `alembic upgrade head --sql`
    - `alembic upgrade head` against CI Postgres service
    - `python -m build`
  - Boots Postgres and Redis service containers.
  - Generates ephemeral RSA keys at runtime for `JWT__PRIVATE_KEY_PEM` and `JWT__PUBLIC_KEY_PEM`.

- `Release Image` (`.github/workflows/release.yml`)
  - Runs on tags (`v*`) and manual dispatch.
  - Builds and pushes container image to GHCR:
    - `ghcr.io/<owner>/auth-service:<tag>`
    - `ghcr.io/<owner>/auth-service:sha-<commit-sha>`
  - If `docker/Dockerfile` is still empty, it exits with a warning and skips image publishing.

- `Deploy` (`.github/workflows/deploy.yml`)
  - Manual dispatch workflow for `staging` or `production`.
  - Applies manifests from `k8s/` to the selected namespace.
  - If manifests are still empty, it exits with a warning and skips deployment.

### Required Secrets

- `KUBE_CONFIG_B64` (for deploy workflow)
  - Base64-encoded kubeconfig contents.
  - Add as repository or environment secret in GitHub.

### Optional Release Input

- `image_tag` in `Release Image` workflow dispatch
  - Overrides default tag derivation when manually triggering release.
