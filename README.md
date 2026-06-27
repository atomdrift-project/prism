<p align="center">
  <img src="media/logo.svg" alt="prism" width="240">
</p>

# prism

Prism is the public-facing web frontend for the atomdrift malware-analysis
pipeline — it powers <https://lab.atomdrift.org/>.

It is a read-mostly rendering layer: it serves the sample feed, per-file
analysis pages, the inline source viewer, and AI reverse-engineering reports
by reading from the **hopper** database (the sample registry and cached
**litmus** analysis results) and streaming file bytes from **hopper-api**.
Browser uploads, when enabled, are analyzed by a **litmus** server and the
result is published back to hopper.

Prism holds no durable state of its own — it is a cache in front of hopper, so
it can run anywhere. In production it runs in a FreeBSD jail (see
[Deployment](#deployment)) behind a Cloudflare Tunnel.

## Build & run

```bash
make build
PORT=8080 ./prism
```

`make dev` runs a local build against the **production** hopper-db and
hopper-api (browsing is read-only, but write actions hit prod — see the
`Makefile` for the exact environment and `~/.pgpass` requirement).
`make dev-watch` does the same with auto-reload via [air](https://github.com/air-verse/air).

## Configuration

Flags win over the matching environment variable.

| Flag | Env | Default | Purpose |
| --- | --- | --- | --- |
| `--port` | `PORT` | `8080` | HTTP listen port |
| `--db` | `HOPPER_DSN` / `FALLOUT_DB` | `postgres://hopper@hopper-db:5432/hopper?sslmode=disable` | hopper PostgreSQL DSN |
| `--hopper-api-addr` | `HOPPER_API_ADDR` | `hopper-api:8081` | hopper-api host:port (file bytes) |
| `--litmus` | `LITMUS_ADDR` | `litmus:49999` | litmus analysis server; empty disables it, falling back to hopper-only analysis |
| `--uploads` | `PRISM_UPLOADS` | off | enable browser uploads via `POST /upload` |
| `--public` | — | off | public-deployment mode: atomdrift lab branding and Secure cookies |
| `--no-cache` | — | off | disable persistent caching (in-memory only) |
| `--rate-limit` | — | `10` | max requests per client IP per window before 429/challenge (0 disables) |
| `--rate-window` | — | `10m` | window over which `--rate-limit` applies |
| — | `PRISM_CSRF_KEY` | — | HMAC key for CSRF tokens (required for uploads) |
| — | `CACHE_DIR` | OS user cache dir | localfs cache location |

## Deployment

Production runs in a FreeBSD jail managed with
[bastille](https://bastille.live/), using separate build and run jails:

```bash
make deploy            # git pull + ./hacks/rollout-bastille.sh build prism
```

The rollout is effectively zero-downtime: the replacement binds the same port
as the running process via `SO_REUSEPORT_LB`, the new process is health-checked
on `/_/health`, and only then is the old one sent `SIGTERM` (it drains
in-flight requests during a 5-second graceful shutdown). See
`hacks/rollout-bastille.sh` for the full sequence and prerequisites
(`hopper-api` / `hopper-db` entries in `/etc/hosts`, `CF_TUNNEL_TOKEN`).

`make deploy` is FreeBSD-only. The binary itself is portable — `make build`
produces a static `CGO_ENABLED=0` binary that runs anywhere Go does.

## Development

```bash
make test          # go test ./...
make integration   # integration tests (live hopper, -tags integration)
make lint          # shellcheck, golangci-lint, yamllint, biome
```

## Hopper Query Discipline

Prism is a read-mostly cache layer in front of the hopper database. To
survive traffic spikes without melting upstream, **every** read against
hopper (DB query or hopper-api HTTP call) must flow through one of the
`fido.TieredCache` wrappers declared in `main.go`. Fido's `Fetch` has
built-in singleflight: N concurrent callers for the same key share one
loader invocation.

Caches:

| Cache | Stored type | What it wraps |
| --- | --- | --- |
| `cache` | `storedResult` | per-SHA litmus analysis envelope |
| `feedCache` | `cachedFeedSnapshot` | every feed query (frontpage, criticality, ecosystem, domain, formula, free-text `?q=`) — memory-only |
| `reportCache` | `cachedReport` | per-SHA AI reverse-engineering report |
| `parentArchiveCache` | `cachedParents` | per-SHA "found in N archives" list |

If you need to add a hopper query, add (or reuse) a cache for it.
Anti-patterns to refuse in code review:

- Calling `hopperDB.Foo(ctx, …)` directly from an HTTP handler.
- Calling `hopperClient.Do(req)` outside a cache loader.
- Using `cache.Get` + `cache.Set` instead of `cache.Fetch` (skips
  singleflight; two concurrent misses run two loaders).
- Failing to cache the not-found result — wrap with a `Found bool`
  flag so SHAs without reports don't refetch every request.
- Storing pre-formatted relative times (`"5 minutes ago"`) in cached
  snapshots; cache the raw `time.Time` and re-derive at render.

Cache TTLs live in the `const` block at the top of `main.go`
(`feedCacheTTL`, `feedPrecacheInterval`, `auxCacheTTL`). See `doc.go`
for the package-level reminder.
</content>
</invoke>
