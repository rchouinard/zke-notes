---
name: Docker & Infrastructure
globs:
    [
        'compose*.yaml',
        'compose*.yml',
        '**/Dockerfile',
        '**/*.Dockerfile',
        '.env*',
        'api/frankenphp/**',
    ]
alwaysApply: false
---

# Docker & Infrastructure Rules

## Compose Files

- `compose.yaml` — base service definitions (php/FrankenPHP, pwa/SPA, database/Postgres).
- `compose.override.yaml` — development overrides (volume mounts for hot reload, debug ports).
- `compose.prod.yaml` — production overrides (no bind mounts, resource limits, restart policies).
- Never put secrets (passwords, JWT keys) directly in `compose.yaml` — reference them from environment variables or `.env` (development only).

## PHP / FrankenPHP Service

- The `php` service runs FrankenPHP and serves both the API and acts as a reverse proxy.
- The `SERVER_NAME` env var controls which domains FrankenPHP listens on.
- `TRUSTED_PROXIES` and `TRUSTED_HOSTS` must be explicitly set in production.

## SPA Service

- The `spa` service serves the built Quasar SPA (or dev server in override).
- `VITE_API_BASE_URL` must point to the PHP service internal address in the Compose network.

## Postgres Service

- Use the `postgres:16-alpine` image.
- Data is persisted in a named volume `database_data` — do not use anonymous volumes.
- Always configure the healthcheck (`pg_isready`) before depending services start.
- `POSTGRES_PASSWORD` must be changed from the default in any non-local environment.

## Vault (Optional)

- If HashiCorp Vault is added to the stack, it is used ONLY for:
    - Storing and rotating the JWT signing secret.
    - Storing database credentials (dynamic secrets pattern).
    - It is NOT used for storing user encryption keys or note ciphertext — those are the user's responsibility and are handled client-side.
- Add Vault as a named service in `compose.yaml` using the official `hashicorp/vault` image with dev mode disabled in production.
- Use the Vault Agent sidecar pattern or `envconsul` to inject secrets into the PHP container environment.

## General

- All services must have explicit `restart: unless-stopped` (production) or `restart: "no"` (development override) policies.
- Use `depends_on` with `condition: service_healthy` for the database dependency.
- Never expose the database port to the host in production (`compose.prod.yaml`).
- `.env` files containing secrets must be in `.gitignore` and never committed.
