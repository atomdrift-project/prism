// Package main is the prism HTTP server: the public-facing rendering
// layer for the atomdrift malware-analysis pipeline. It reads from the
// hopper database (sample registry + cached cleave/litmus results) and
// streams source bytes from hopper-api.
//
// # Hopper Query Discipline (read this before adding any new query)
//
// Every read against hopper — DB row fetch, HTTP call to hopper-api,
// anything that could be triggered N times by N concurrent users hitting
// the same URL — MUST go through one of the fido TieredCache wrappers
// declared at the top of main.go:
//
//   - cache              storedResult (per-SHA analysis envelope)
//   - feedCache          cachedFeedSnapshot (any feed query, keyed by filters)
//   - contentCache       cachedContent (per-SHA file body for inline source view)
//   - reportCache        cachedReport (per-SHA AI report)
//   - parentArchiveCache cachedParents (per-SHA "found in N archives" list)
//
// Use TieredCache.Fetch / FetchTTL with a loader closure. Fido's Fetch
// has built-in singleflight: 100 concurrent calls for the same key share
// one loader invocation, the other 99 wait on the result. This is how
// prism survives traffic spikes without melting hopper.
//
// Anti-patterns to refuse in code review:
//
//   - Calling hopperDB.Foo(ctx, …) directly from an HTTP handler. Wrap
//     it in a per-SHA (or per-query-shape) cached helper instead.
//   - Calling hopperClient.Do(req) outside contentCache.Fetch. Cache the
//     bytes, even if you think this endpoint is "rare."
//   - Using cache.Get + cache.Set as a substitute for cache.Fetch. That
//     skips the singleflight; two concurrent misses run two loaders.
//   - Caching pre-formatted relative time strings ("5 minutes ago").
//     Cache the raw time.Time and re-derive at render time, or accept
//     bounded staleness equal to the TTL.
//
// Cache-miss "not found" results SHOULD be cacheable too — wrap with a
// `Found bool` (see cachedReport) or use an empty-slice sentinel (see
// cachedParents). Otherwise a SHA that legitimately has no report will
// fan out to a fresh hopper hit on every render.
//
// TTLs live in the const block near the top of main.go:
//
//   - feedCacheTTL        3 minutes (every feed query)
//   - feedPrecacheInterval 90 seconds (how often the pre-warm loop ticks)
//   - auxCacheTTL         3 minutes (report, parent archives)
//
// The pre-warm goroutine (refreshFeedCacheLoop) only covers the high-
// traffic feed variants (default + 3 criticalities). Everything else
// caches on first request and stays for one TTL window.
//
// If you find yourself wanting a query that can't fit this pattern, ask
// before merging — the answer is almost always a new cache, not a
// bypass.
package main
