package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
)

// packageSearchPURLs tries the identities the catalog's registries would assign
// to this name. SourcePURLIdentity is the same resolver used at ingestion; no
// suffix scan or package-name index is needed. Include the language registries
// even when their last arrival is outside the ecosystem dropdown's window.
func packageSearchPURLs(name string, ecosystems, domains []string) []string {
	if name == "" || strings.ContainsAny(name, " \t\r\n") {
		return nil
	}
	var candidates []string
	add := func(ecosystem, domain string) {
		if purl, ok := pkgparse.SourcePURLIdentity(ecosystem, domain, name); ok {
			candidates = append(candidates, purl)
		}
	}
	for _, ecosystem := range []string{"npm", "pypi", "gem", "cargo", "golang", "maven", "nuget", "composer"} {
		add(ecosystem, "")
	}
	for _, ecosystem := range ecosystems {
		add(ecosystem, "")
	}
	for _, domain := range domains {
		add("", domain)
	}
	slices.Sort(candidates)
	return slices.Compact(candidates)
}

// resolvePackageSearch performs one index probe per candidate, stopping at the
// first release of each identity. Resolve before applying verdict/version filters
// so an existing package with no matching releases stays empty instead of falling
// through to unrelated filenames. Every matching ecosystem is retained.
func resolvePackageSearch(ctx context.Context, db *hopper.DB, candidates []string) ([]string, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	if pool := db.Pool(); pool != nil {
		rows, err := pool.Query(ctx, `SELECT candidate FROM unnest($1::text[]) AS c(candidate)
			WHERE EXISTS (SELECT 1 FROM samples WHERE purl_base <> '' AND purl_base = candidate)`, candidates)
		if err != nil {
			return nil, fmt.Errorf("resolve package search: %w", err)
		}
		defer rows.Close()
		var found []string
		for rows.Next() {
			var purl string
			if err := rows.Scan(&purl); err != nil {
				return nil, err
			}
			found = append(found, purl)
		}
		return found, rows.Err()
	}
	// SQLite is used by local fixtures; PostgreSQL above is the serving path.
	var found []string
	for _, candidate := range candidates {
		rows, err := db.FeedSamples(ctx, &hopper.FeedQuery{PURLBase: candidate, Limit: 1})
		if err != nil {
			return nil, err
		}
		if len(rows) != 0 {
			found = append(found, candidate)
		}
	}
	return found, nil
}

// feedSummaryColumns is Prism's table read model. Keep verdict scalar fields
// (including legacy formats), but never transfer per-member analysis arrays or
// the detail page's trait graph. A litellm feed formerly transferred 42 MB of ML
// JSON for a 245 kB snapshot. Detail lookups still use Hopper's full projection.
const feedSummaryColumns = `sha256, filename, path, file_type, source, feed, ecosystem,
	package, version, purl_base, formula, litmus_score,
	litmus_result - ARRAY['files', 'fs', 'mods']::text[] AS litmus_result,
	llm_result, COALESCE(top_traits, ''), created_at,
	COALESCE(provenance->'registry'->'record'->>'title', ''),
	COALESCE(LEFT(provenance->'registry'->'record'->>'description', 300), ''),
	COALESCE((provenance->'registry'->'record'->>'downloads_total')::bigint, 0), corroborated`

// feedSummaryQuery uses literal predicates for active filters, so PostgreSQL can
// use the partial feed/PURL indexes even after a statement gets a generic plan.
// Values always remain bound parameters. This query belongs to the UI because
// its projection is deliberately smaller than Hopper's general Sample API.
func feedSummaryQuery(filter *hopper.FeedQuery, purls []string) (query string, args []any) {
	where := []string{"cleave_result IS NOT NULL", "file_type <> 'registry'"}
	bind := func(value any) string {
		args = append(args, value)
		return fmt.Sprintf("$%d", len(args))
	}
	equal := func(column, value string) {
		if value != "" {
			where = append(where, column+" = "+bind(value))
		}
	}
	array := func(column string, values any, n int, first any) {
		if n == 1 {
			where = append(where, column+" = "+bind(first))
		} else if n > 1 {
			where = append(where, column+" = ANY("+bind(values)+")")
		}
	}
	equal("source", filter.Source)
	equal("label", filter.Label)
	equal("formula", filter.Formula)
	for _, filter := range []struct {
		column string
		values []string
	}{{"feed", filter.Feeds}, {"ecosystem", filter.Ecosystems}, {"domain", filter.Domains}} {
		if len(filter.values) > 0 {
			array(filter.column, filter.values, len(filter.values), filter.values[0])
		}
	}
	if len(filter.LitmusClasses) > 0 {
		array("litmus_class", filter.LitmusClasses, len(filter.LitmusClasses), filter.LitmusClasses[0])
	}
	if filter.RequireLitmus || len(filter.LitmusClasses) > 0 && !slices.Contains(filter.LitmusClasses, 0) {
		where = append(where, "litmus_result IS NOT NULL")
	}
	if filter.TopLevelOnly {
		where = append(where, `parent = '' AND NOT EXISTS (
			SELECT 1 FROM sample_locations sl WHERE sl.sha256 = samples.sha256
			AND sl.parent_sha256 <> '' AND sl.rel IN ('', 'unpacked'))`)
	}
	if filter.Corroborated {
		where = append(where, "corroborated")
	}
	equal("purl_base", filter.PURLBase)
	equal("version", filter.PURLVersion)
	if len(purls) > 0 {
		array("purl_base", purls, len(purls), purls[0])
	}
	if filter.PURLBase != "" || len(purls) > 0 {
		where = append(where, "purl_base <> ''")
	}
	if filter.Search != "" {
		term := strings.ToLower(filter.Search)
		pattern := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(term)
		where = append(where, "(filename ILIKE '%' || "+bind(pattern)+" || '%' ESCAPE '\\' OR sha256 = "+bind(term)+" OR package = "+bind(term)+")")
	}
	if filter.ClaimName != "" || filter.ClaimSigner != "" {
		claim := "EXISTS (SELECT 1 FROM asset_claims ac WHERE ac.sha256 = samples.sha256"
		if filter.ClaimName != "" {
			claim += " AND ac.name = " + bind(filter.ClaimName)
		}
		if filter.ClaimSigner != "" {
			claim += " AND ac.signer = " + bind(filter.ClaimSigner)
		}
		where = append(where, claim+")")
	}
	if !filter.Since.IsZero() {
		where = append(where, "created_at >= "+bind(filter.Since))
	}
	if !filter.Until.IsZero() {
		where = append(where, "created_at < "+bind(filter.Until))
	}
	order := "mtime DESC NULLS LAST"
	switch filter.OrderBy {
	case "created_at":
		order = "created_at DESC"
	case "analyzed_at":
		order = "analyzed_at DESC NULLS LAST"
	default:
		// Match Hopper's default ordering for callers without an explicit sort.
	}
	query = "SELECT " + feedSummaryColumns + " FROM samples WHERE " + strings.Join(where, " AND ") +
		" ORDER BY " + order + " LIMIT " + bind(max(1, min(filter.Limit, 1000))) + " OFFSET " + bind(max(filter.Offset, 0))
	return query, args
}

func feedSummarySamples(ctx context.Context, db *hopper.DB, q *hopper.FeedQuery, purls []string) ([]*hopper.Sample, error) {
	// A substring search without the optional trigram index must not hold the
	// browser for a minute. Package/PURL queries keep the normal read deadline.
	if q.Search != "" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}
	if db.Pool() == nil {
		if len(purls) == 0 {
			return db.FeedSamples(ctx, q)
		}
		var samples []*hopper.Sample
		for _, purl := range purls {
			if q.PURLBase != "" && q.PURLBase != purl {
				continue
			}
			query := *q
			query.PURLBase = purl
			rows, err := db.FeedSamples(ctx, &query)
			if err != nil {
				return nil, err
			}
			samples = append(samples, rows...)
		}
		slices.SortFunc(samples, func(a, b *hopper.Sample) int { return b.CreatedAt.Compare(a.CreatedAt) })
		return samples[:min(len(samples), max(1, q.Limit))], nil
	}
	query, args := feedSummaryQuery(q, purls)
	rows, err := db.Pool().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("feed summaries: %w", err)
	}
	defer rows.Close()
	var samples []*hopper.Sample
	for rows.Next() {
		sample := &hopper.Sample{}
		if err := rows.Scan(&sample.SHA256, &sample.Filename, &sample.Path, &sample.FileType,
			&sample.Source, &sample.Feed, &sample.Ecosystem, &sample.Package, &sample.Version,
			&sample.PURLBase, &sample.Formula, &sample.LitmusScore, &sample.LitmusResult,
			&sample.LLMResult, &sample.TopTraits, &sample.CreatedAt, &sample.RegistryTitle,
			&sample.RegistryDescription, &sample.RegistryDownloads, &sample.Corroborated); err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}
