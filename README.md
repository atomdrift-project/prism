# prism

Prism is the read-mostly web frontend for the Atomdrift malware-analysis
pipeline and powers [lab.atomdrift.org](https://lab.atomdrift.org/). It renders
hopper's sample feed, analysis details, source views, and AI-assisted reports;
it does not maintain its own authoritative sample database.

This repository is for operators running the Atomdrift lab stack. To scan files
locally, install [Atomdrift Scan](https://github.com/atomdrift-project/scan).

## Architecture

```text
browser ──► prism ──► hopper PostgreSQL (verdict schema, read-only)
                 ├──► hopper API (sample bytes, rescans, and uploads)
                 ├──► Beamline API (browser uploads and analysis)
                 └──► Atomdrift Scan server (optional escalation)
```

Prism reads hopper's verdict schema directly, through hopper's `store`
package, so its pages never wait on hopper's API; its sessions are read-only to
the server, and every write goes through the API. Where the API answers a
question (a file's verdict, the sightings ledger), prism asks the same library
function the API does, so a page and an API answer agree.

Prism caches rendered data locally but treats hopper as the source of truth.
Browser uploads are disabled by default. When enabled, Prism sends raw file
bytes to the public Beamline API at `https://api.isotope13.ai`; the resulting
artifact and report are rendered through Hopper's normal result path.

## Requirements

- Go 1.26 or newer
- Network access to hopper PostgreSQL and hopper's HTTP API
- Beamline API access and Hopper's HTTP API if uploads are enabled
- An Atomdrift Scan HTTP service only if local escalation is enabled
- A persistent cache directory for production deployments

## Build and test

```bash
make build
make test
make lint
```

The database tests create hopper's verdict schema in a disposable PostgreSQL
database and skip without one; hopper's throwaway cluster serves:

```bash
PRISM_TEST_PG_DSN="$(../hopper/scripts/test-pg.sh)" make test
```

## Run locally

```bash
HOPPER_DSN='postgres://hopper@localhost:5432/hopper?sslmode=disable' \
HOPPER_API_ADDR='localhost:8081' \
./prism --listen 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080/>. Leave uploads disabled until Hopper, Beamline,
and the CSRF key are configured.

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
| `--schema` | `HOPPER_SCHEMA` | `verdict` | Schema holding hopper's verdict tables |
| `--hopper-api-addr` | `HOPPER_API_ADDR` | `hopper-api:8081` | Hopper file, rescan, and upload API |
| `--beamline-api-addr` | `BEAMLINE_API_ADDR` | `https://api.isotope13.ai` | Beamline upload/analysis API |
| `--uploads` | `PRISM_UPLOADS` | off | Enable browser uploads |
| `--public` | — | off | Public branding and secure-cookie behavior |
| `--no-cache` | — | off | Disable persistent cache storage |
| `--rate-limit` | — | `10` | Requests per client window; `0` disables |
| `--rate-window` | — | `10m` | Rate-limit window |
| — | `PRISM_CSRF_KEY_FILE` | — | File containing the upload/action HMAC key |
| — | `CACHE_DIR` | OS cache directory | Persistent cache location |

## Viewed-sample escalation

When a browser waits on an unanalyzed sample, Prism asks hopper to promote it
ahead of the ordinary backlog.

Escalation is deduplicated, rate-limited, and triggered through the browser's
wait channel rather than an ordinary detail-page request. This prevents
crawlers from promoting the entire feed.

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
