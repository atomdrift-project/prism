<p align="center">
  <img src="media/logo.svg" alt="prism" width="240">
</p>

# prism

Web interface for binary static analysis using cleave and rizin.

## Usage

```bash
make build
PORT=8080 ./prism
```

Requires `cleave` (cleave analysis server) and `rizin` in PATH.

## Environment Variables

- `PORT` - HTTP port (default: 8080)
- `GCS_BUCKET` - GCS bucket for uploads (optional)
- `CLEAVE_PATH` / `CLEAVE_ADDR` - Path to cleave binary or server address

## Deploy

```bash
make deploy GCP_PROJECT=my-project GCS_BUCKET=my-bucket
```

## Development

```bash
make lint   # Run golangci-lint
make test   # Run tests
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
| `cache` | `storedResult` | per-SHA cleave/litmus envelope |
| `feedCache` | `cachedFeedSnapshot` | every feed query (frontpage, criticality, ecosystem, domain, formula) |
| `contentCache` | `cachedContent` | per-SHA file body for the inline source viewer |
| `reportCache` | `cachedReport` | per-SHA AI reverse-engineering report |
| `parentArchiveCache` | `cachedParents` | per-SHA "found in N archives" list |

If you need to add a hopper query, add (or reuse) a cache for it.
Anti-patterns to refuse in code review:

- Calling `hopperDB.Foo(ctx, …)` directly from an HTTP handler.
- Calling `hopperClient.Do(req)` outside `contentCache.Fetch`.
- Using `cache.Get` + `cache.Set` instead of `cache.Fetch` (skips
  singleflight; two concurrent misses run two loaders).
- Failing to cache the not-found result — wrap with a `Found bool`
  flag so SHAs without reports don't refetch every request.
- Storing pre-formatted relative times (`"5 minutes ago"`) in cached
  snapshots; cache the raw `time.Time` and re-derive at render.

Cache TTLs live in the `const` block at the top of `main.go`:
`feedCacheTTL`, `feedPrecacheInterval`, `auxCacheTTL`. See `doc.go`
for the package-level reminder.
