# coraza-traefik-middleware

[Coraza](https://coraza.io/) WAF as a [forward-auth](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) middleware for [Traefik](https://traefik.io/). Incoming requests are sent to this service first; if the WAF allows the request, Traefik forwards it to your backend. Blocked requests receive 403 Forbidden.

## Features

- **Forward-auth compatible** — Implements the Traefik forward-auth contract (200 = allow, 4xx/5xx = deny).
- **OWASP ModSecurity Core Rule Set (CRS)** — Uses [coraza-coreruleset](https://github.com/corazawaf/coraza-coreruleset) for rule coverage.
- **Configurable rules** — WAF behavior is driven by the `DIRECTIVES` environment variable (SecRuleEngine, CRS includes, etc.).
- **Audit logging** — Writes Coraza audit logs to a file with configurable retention and background processing.
- **Admin server** — Separate HTTP server with `/health` and Prometheus `/metrics` for observability.
- **Proxy headers** — Honors `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and related headers from Traefik.

## Requirements

- **Go 1.25+** for building and unit tests.
- **Docker & Docker Compose** for running the stack and integration tests.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WAF_PORT` | `8080` | Port for the WAF (forward-auth) server. |
| `ADMIN_PORT` | `8081` | Port for the admin server (health, metrics). |
| `LOG_LEVEL` | `info` | Application log level: `debug`, `info`, `warn`, `error`. |
| `DIRECTIVES` | *(required)* | ModSecurity-style directives (multi-line), including `SecRuleEngine On` and CRS includes. |
| `AUDIT_LOG_PATH` | `/var/log/coraza-audit.log` | Path for the Coraza audit log file. |
| `AUDIT_LOG_EXPIRATION` | `24h` | How long to keep audit log entries before expiration. |
| `AUDIT_LOG_EXPIRATION_JOB_INTERVAL` | `1h` | Interval for the expiration job. |
| `AUDIT_LOG_PROCESSING_JOB_INTERVAL` | `10s` | Interval for processing/parsing audit logs. |

## Traefik setup

1. Run the middleware (e.g. via Docker) so it listens on `WAF_PORT` (e.g. `8080`).
2. Add a **forwardAuth** middleware in your Traefik config (as shown below).

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: coraza-traefik-middleware
  namespace: coraza
spec:
  forwardAuth:
    address: http://coraza-traefik-middleware.coraza.svc.cluster.local:8080
    forwardBody: true
```

3. Add the middleware to your Traefik entrypoints.

## Building and running

**Pre-built image (GitHub Container Registry):**

A container image is published to [GitHub Container Registry](https://ghcr.io) on each [release](https://github.com/chairswithlegs/coraza-traefik-middleware/releases). Pull a specific version or `latest`:

```bash
docker pull ghcr.io/chairswithlegs/coraza-traefik-middleware:v1.0.0
# or
docker pull ghcr.io/chairswithlegs/coraza-traefik-middleware:latest
```

**Local (no Docker):**

```bash
go build -o coraza-traefik-middleware ./src
./coraza-traefik-middleware
```

Set `DIRECTIVES` (and optionally other env vars) before running.

**Docker Compose (Traefik + middleware + whoami):**

```bash
make run    # or: docker compose up -d --build
```

- Traefik: `http://localhost:8000`
- WAF (forward-auth): inside network at `http://coraza-traefik-middleware:8080`
- Admin (health/metrics): `http://localhost:8081`

Stop the stack:

```bash
make stop   # or: docker compose down
```

## Testing

- **Unit tests:** `make test` (or `go test ./...`).
- **Integration tests:** Start the stack with `make run`, then run `make integration-test` (or `go test -tags=integration ./tests/`).
