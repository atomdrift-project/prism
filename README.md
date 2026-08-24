# prism

Prism is the read-mostly web frontend for the Atomdrift malware-analysis
pipeline and powers [lab.atomdrift.org](https://lab.atomdrift.org/). It renders
hopper's sample feed, analysis details, source views, and AI-assisted reports;
it does not maintain its own authoritative sample database.

This repository is for operators running the Atomdrift lab stack. To scan files
locally, install [Atomdrift Scan](https://github.com/atomdrift-project/scan).

## Architecture

```text
browser ──► prism ──► hopper PostgreSQL
                 ├──► hopper API (sample bytes and queue actions)
                 └──► Atomdrift Scan server (optional uploads/escalation)
```

Prism caches rendered data locally but treats hopper as the source of truth.
Browser uploads are disabled by default. When enabled, Prism sends them to a
configured Atomdrift Scan server and publishes the resulting report to hopper.

## Requirements

- Go 1.26 or newer
- Network access to hopper PostgreSQL and hopper's HTTP API
- An Atomdrift Scan HTTP service if uploads or local escalation are enabled
- A persistent cache directory for production deployments

## Build and test

```bash
make build
make test
make lint
```

## Run locally

```bash
HOPPER_DSN='postgres://hopper@localhost:5432/hopper?sslmode=disable' \
HOPPER_API_ADDR='localhost:8081' \
./prism --listen 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080/>. Leave uploads disabled until a scan service and
CSRF key are configured.

The Fallout log is also available as JSON at `/fallout.json` (or
`/api/fallout`). It returns every qualifying catch with the full `sha256` and
PURL for triage; `?verified=0` keeps only uncorroborated catches and
`?verified=1` keeps only corroborated ones. Verification filtering happens
after the same cached hostile snapshot used by `/fallout`, so it does not
create a separate feed query or cache entry.

`make dev` uses the production hopper endpoints defined by the Makefile. Read
those settings before running it: browsing is read-only, but rescan and upload
actions can change production state.

## Configuration

Flags override matching environment variables.

| Flag | Environment | Default | Purpose |
| --- | --- | --- | --- |
| `--listen` | `LISTEN_ADDR` | all interfaces | HTTP listen address |
| `--port` | `PORT` | `8080` | HTTP port |
| `--db` | `HOPPER_DSN` / `FALLOUT_DB` | production-style hopper DSN | Hopper PostgreSQL connection |
| `--hopper-api-addr` | `HOPPER_API_ADDR` | `hopper-api:8081` | Hopper file and queue API |
| `--litmus` | `LITMUS_ADDR` | `scan:49999` | Atomdrift Scan server; empty disables it |
| `--uploads` | `PRISM_UPLOADS` | off | Enable browser uploads |
| `--no-escalate-scan` | `PRISM_NO_ESCALATE_SCAN` | off | Queue viewed samples without also scanning locally |
| `--public` | — | off | Public branding and secure-cookie behavior |
| `--no-cache` | — | off | Disable persistent cache storage |
| `--rate-limit` | — | `10` | Requests per client window; `0` disables |
| `--rate-window` | — | `10m` | Rate-limit window |
| — | `PRISM_CSRF_KEY_FILE` | — | File containing the upload/action HMAC key |
| — | `CACHE_DIR` | OS cache directory | Persistent cache location |

`--litmus` and `LITMUS_ADDR` retain the scanner's former internal name for
configuration compatibility; their value points to the current `atomscan
serve` service.

## Viewed-sample escalation

When a browser waits on an unanalyzed sample, Prism asks hopper to promote it
ahead of the ordinary backlog. If a healthy Scan server is configured, Prism
can also fetch the bytes, verify their SHA-256, scan them, and publish the
result. `--no-escalate-scan` keeps promotion but disables that local scan path.

Escalation is deduplicated, rate-limited, size-limited, and triggered through
the browser's wait channel rather than an ordinary detail-page request. This
prevents crawlers from promoting the entire feed.

## Deployment

```bash
make deploy
```

Deployment scripts support hardened systemd services on Linux and Bastille
jails on FreeBSD. They encode Atomdrift's production assumptions, including
Cloudflare Tunnel, hopper hostnames, credentials, and cache paths. Review the
selected script and supply secrets through its documented credential mechanism
before running it.

Prism handles malware downloads, database access, rescan actions, and optional
uploads. Keep it behind an authenticated/restricted hopper network and a
properly configured public reverse proxy; do not expose hopper PostgreSQL or
the hopper API directly.
