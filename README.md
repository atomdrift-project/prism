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
| `--listen` | `LISTEN_ADDR` | all interfaces | HTTP listen address |
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
| — | `PRISM_CSRF_KEY_FILE` | — | file containing the HMAC key; preferred over `PRISM_CSRF_KEY` |
| — | `CACHE_DIR` | OS user cache dir | localfs cache location |

Prism probes hopper-api and litmus once per process every 15 seconds, using
their liveness endpoints. Page requests only read the shared atomic result:
hopper-api outages disable downloads, and uploads are disabled unless both
hopper-api and litmus are available. Feed and result rendering remain
independent of these probes.

## Deployment

`make deploy` selects the native rollout for the host OS.

On Linux (systemd 249 or newer) it builds and tests locally, then installs a
hardened systemd service using `doas` or `sudo` when needed. For the first
deployment, provide the PostgreSQL password; the upstream `hopper-db` primary
is the default:

```bash
CF_TUNNEL_TOKEN='...' HOPPER_DB_HOST=hopper-db HOPPER_DB_PASS='...' make deploy
```

The selected host is persisted in `/etc/prism/prism.env`. Later deploys reuse
both it and `/etc/prism/pgpass`, so the password does not need to be supplied
again. If the invoking account already has an exact matching entry in
`$PGPASSFILE` or `~/.pgpass`, the first deploy imports only that entry into the
root-only service credential instead. The Linux DSN forces PostgreSQL
transactions read-only even when it points at the primary. PostgreSQL and CSRF
secrets are exposed to prism through systemd's read-only credential directory,
not its environment or command line.
The service runs under a transient systemd identity with no capabilities, a
read-only filesystem, syscall/address-family/device/namespace restrictions,
and a single writable systemd-managed directory at `/var/cache/prism` for fido
caches. It binds only `127.0.0.1:8080`.

The rollout also installs (through an already-configured host package manager
when necessary) and manages `cloudflared.service`. The tunnel token is
persisted as a root-only file and supplied through a systemd credential;
cloudflared 2025.4.0 or newer is required for token-file support. Configure
the remotely-managed tunnel's public hostname in the Cloudflare dashboard with
`http://127.0.0.1:8080` as its origin. Later deploys reuse the saved token.
Ensure `hopper-db`, `hopper-api`, and (when enabled) `scan` resolve on the Linux
host.

Useful commands:

```bash
systemctl status prism
systemctl status cloudflared
journalctl -u prism -f
journalctl -u cloudflared -f
systemd-analyze security prism.service
systemd-analyze security cloudflared.service
```

On FreeBSD, production uses [bastille](https://bastille.live/) with separate
build and run jails:

```bash
make deploy            # git pull + ./hacks/rollout-bastille.sh build prism
```

The rollout is effectively zero-downtime: the replacement binds the same port
as the running process via `SO_REUSEPORT_LB`, the new process is health-checked
on `/_/health`, and only then is the old one sent `SIGTERM` (it drains
in-flight requests during a 5-second graceful shutdown). See
`hacks/rollout-bastille.sh` for the full sequence and prerequisites
(`hopper-api` / `hopper-db` entries in `/etc/hosts`, `CF_TUNNEL_TOKEN`).

The binary itself is portable — `make build` produces a static
`CGO_ENABLED=0` binary that runs anywhere Go does.

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
