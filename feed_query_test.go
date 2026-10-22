package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
)

func TestPackageSearchPURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"litellm", []string{"pkg:pypi/litellm", "pkg:conda/litellm", "pkg:alpm/arch/litellm"}},
		{"@scope/pkg", []string{"pkg:npm/%40scope/pkg"}},
		{"my_project", []string{"pkg:pypi/my-project"}},
		{"vendor/package", []string{"pkg:composer/vendor/package"}},
		{"org.example:library", []string{"pkg:maven/org.example/library"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := packageSearchPURLs(tc.name, []string{"python", "pypi", "conda", "arch"}, []string{"pythonhosted.org"})
			for _, purl := range tc.want {
				if !slices.Contains(got, purl) {
					t.Errorf("missing identity %q in %v", purl, got)
				}
			}
			if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
				t.Fatalf("candidates must be sorted and unique: %v", got)
			}
		})
	}
	for _, term := range []string{"", "two words", "line\nbreak"} {
		if got := packageSearchPURLs(term, nil, nil); len(got) != 0 {
			t.Errorf("free text %q produced identities %v", term, got)
		}
	}
}

// These regressions run the serving SQL, rather than reproducing its logic in
// mocks. Point PRISM_FEED_TEST_DSN at a test PostgreSQL; all fixtures are temporary
// tables on a single connection, and disappear when the test closes that pool.
func newFeedPostgres(t *testing.T) *hopper.DB {
	t.Helper()
	dsn := os.Getenv("PRISM_FEED_TEST_DSN")
	if dsn == "" {
		t.Skip("set PRISM_FEED_TEST_DSN to run PostgreSQL feed regressions")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	params := u.Query()
	params.Set("pool_max_conns", "1")
	u.RawQuery = params.Encode()
	db, err := hopper.Open(t.Context(), u.String(), "prism-feed-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	_, err = db.Pool().Exec(t.Context(), `CREATE TEMP TABLE samples (
		sha256 text PRIMARY KEY, filename text NOT NULL DEFAULT '', path text NOT NULL DEFAULT '',
		file_type text NOT NULL DEFAULT 'python', source text NOT NULL DEFAULT 'forager',
		feed text NOT NULL DEFAULT '', ecosystem text NOT NULL DEFAULT 'pypi',
		package text NOT NULL DEFAULT '', version text NOT NULL DEFAULT '', purl_base text NOT NULL DEFAULT '',
		formula text NOT NULL DEFAULT '', litmus_score double precision NOT NULL DEFAULT 0.99,
		cleave_result jsonb DEFAULT '{}', litmus_result jsonb, llm_result jsonb,
		top_traits text DEFAULT '', trait_graph text DEFAULT '', provenance jsonb,
		created_at timestamptz NOT NULL DEFAULT now(), mtime timestamptz, analyzed_at timestamptz,
		parent text NOT NULL DEFAULT '', label text NOT NULL DEFAULT '', domain text NOT NULL DEFAULT '',
		litmus_class integer DEFAULT 2, corroborated boolean NOT NULL DEFAULT false);
		CREATE INDEX ON samples(purl_base) WHERE purl_base <> '';
		CREATE TEMP TABLE sample_locations (sha256 text, parent_sha256 text, rel text);
		CREATE TEMP TABLE asset_claims (sha256 text, name text, signer text);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func insertFeedFixture(t *testing.T, db *hopper.DB, sha, purl, version, filename, ml string) {
	t.Helper()
	_, err := db.Pool().Exec(t.Context(), `INSERT INTO samples
		(sha256,purl_base,package,version,filename,litmus_result) VALUES ($1,$2,'litellm',$3,$4,$5::jsonb)`,
		sha, purl, version, filename, ml)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFeedPostgresPackageSearch(t *testing.T) {
	db := newFeedPostgres(t)
	ctx := t.Context()
	const verdict = `{"v":"7","lvl":20,"conf":97}`
	insertFeedFixture(t, db, "pypi", "pkg:pypi/litellm", "1.0", "unrelated.whl", verdict)
	insertFeedFixture(t, db, "npm", "pkg:npm/litellm", "2.0", "unrelated.tgz", verdict)
	insertFeedFixture(t, db, "filename", "pkg:pypi/something-else", "1.0", "litellm-incident.zip", verdict)
	purls, err := resolvePackageSearch(ctx, db, packageSearchPURLs("litellm", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(purls)
	if !slices.Equal(purls, []string{"pkg:npm/litellm", "pkg:pypi/litellm"}) {
		t.Fatalf("resolved identities = %v", purls)
	}
	q := &hopper.FeedQuery{OrderBy: "created_at", Limit: 100, RequireLitmus: true, TopLevelOnly: true}
	rows, err := feedSummarySamples(ctx, db, q, purls)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want both package identities, excluding filename collision; got %d", len(rows))
	}
	q.PURLVersion = "1.0"
	rows, err = feedSummarySamples(ctx, db, q, purls)
	if err != nil || len(rows) != 1 || rows[0].SHA256 != "pypi" {
		t.Fatalf("version filter: rows=%v error=%v", rows, err)
	}
	q.LitmusClasses = []int{0}
	rows, err = feedSummarySamples(ctx, db, q, purls)
	if err != nil || len(rows) != 0 {
		t.Fatalf("empty verdict band must stay empty: rows=%v error=%v", rows, err)
	}
	missing, err := resolvePackageSearch(ctx, db, packageSearchPURLs("no-such-package", nil, nil))
	if err != nil || len(missing) != 0 {
		t.Fatalf("unknown package = %v, %v", missing, err)
	}
	q = &hopper.FeedQuery{Search: "litellm-incident", Limit: 100}
	rows, err = feedSummarySamples(ctx, db, q, nil)
	if err != nil || len(rows) != 1 || rows[0].SHA256 != "filename" {
		t.Fatalf("filename fallback: rows=%v error=%v", rows, err)
	}
	// LIKE metacharacters must stay literal, not turn into a match-all scan.
	q.Search = "%"
	rows, err = feedSummarySamples(ctx, db, q, nil)
	if err != nil || len(rows) != 0 {
		t.Fatalf("literal percent: rows=%v error=%v", rows, err)
	}
}

func TestFeedPostgresSummaryPreservesVerdicts(t *testing.T) {
	db := newFeedPostgres(t)
	for i, ml := range []string{
		`{"v":"7","lvl":20,"conf":97,"files":[{"id":1,"prob":0.95}],"mods":[{"cls":2}]}`,
		`{"v":"6","l":100,"conf":89,"fs":[{"id":1,"l":100}]}`,
		`{"v":"7","lvl":null,"conf":99,"files":[{"id":1}]}`,
		`{"v":"7","lvl":-1,"conf":90,"files":[{"id":1}]}`,
		`{"v":"5","class":2,"threshold":0.8,"level":20,"fs":[{"id":1,"class":2}]}`,
		`{"v":"4","class":1,"thresholds":[0.6,0.9],"fs":[{"id":1,"class":1}]}`,
	} {
		sha := fmt.Sprintf("verdict-%d", i)
		insertFeedFixture(t, db, sha, "pkg:pypi/litellm", "1.0", "package.whl", ml)
		q := &hopper.FeedQuery{PURLBase: "pkg:pypi/litellm", Limit: 100}
		rows, err := feedSummarySamples(t.Context(), db, q, nil)
		if err != nil {
			t.Fatal(err)
		}
		index := slices.IndexFunc(rows, func(s *hopper.Sample) bool { return s.SHA256 == sha })
		if index < 0 {
			t.Fatalf("missing fixture %s", sha)
		}
		got := rows[index]
		full := &hopper.Sample{LitmusResult: []byte(ml)}
		var before, after litmusMlResponse
		if err := json.Unmarshal(full.LitmusResult, &before); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(got.LitmusResult, &after); err != nil {
			t.Fatal(err)
		}
		bs, bh, bc := sampleMLVerdict(full)
		as, ah, ac := sampleMLVerdict(got)
		if before.verdictClass() != after.verdictClass() || bs != as || bh != ah || bc != ac {
			t.Errorf("summary changed verdict/confidence: before=%s after=%s", ml, got.LitmusResult)
		}
		if len(after.Files) != 0 || got.TraitGraph != "" || len(got.CleaveResult) != 0 {
			t.Errorf("detail-only data leaked into feed: %+v", got)
		}
	}
}

func TestFeedPostgresFilters(t *testing.T) {
	if CriticalLevel != hopper.CriticalLevel {
		t.Fatal("feed summary class filter must use Prism's severity policy")
	}
	db := newFeedPostgres(t)
	ctx := t.Context()
	for _, sha := range []string{"standalone", "contained", "fetched", "registry", "benign"} {
		insertFeedFixture(t, db, sha, "pkg:pypi/litellm", "1.0", "package.whl", `{"v":"7","lvl":20}`)
	}
	_, err := db.Pool().Exec(ctx, `UPDATE samples SET corroborated=true, formula='C2H6', domain='pypi.org',
		feed='test',label='bad',created_at='2026-10-21T12:00:00Z';
		UPDATE samples SET file_type='registry' WHERE sha256='registry';
		UPDATE samples SET litmus_class=0,litmus_result=NULL WHERE sha256='benign';
		INSERT INTO sample_locations VALUES ('contained','archive','unpacked'),('fetched','archive','fetched');
		INSERT INTO asset_claims VALUES ('contained','Example app','Example signer');`)
	if err != nil {
		t.Fatal(err)
	}
	q := &hopper.FeedQuery{
		TopLevelOnly: true, LitmusClasses: []int{2}, Corroborated: true, Formula: "C2H6",
		Source: "forager", Label: "bad", Feeds: []string{"test"}, Ecosystems: []string{"pypi"},
		Domains: []string{"pypi.org"}, Since: time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		Until: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC), OrderBy: "created_at", Limit: 100,
	}
	rows, err := feedSummarySamples(ctx, db, q, nil)
	if err != nil || len(rows) != 2 {
		t.Fatalf("top-level filtered feed: rows=%v error=%v", rows, err)
	}
	q.TopLevelOnly = false
	q.ClaimName, q.ClaimSigner = "Example app", "Example signer"
	rows, err = feedSummarySamples(ctx, db, q, nil)
	if err != nil || len(rows) != 1 || rows[0].SHA256 != "contained" {
		t.Fatalf("claim search must include archive members: rows=%v error=%v", rows, err)
	}
	q = &hopper.FeedQuery{TopLevelOnly: true, LitmusClasses: []int{0}, Limit: 100}
	rows, err = feedSummarySamples(ctx, db, q, nil)
	if err != nil || len(rows) != 1 || rows[0].SHA256 != "benign" {
		t.Fatalf("benign band must retain NULL ML rows: rows=%v error=%v", rows, err)
	}
}

func TestFeedPostgresSummarySize(t *testing.T) {
	db := newFeedPostgres(t)
	bulk := strings.Repeat("x", 2*1024*1024)
	ml := `{"v":"7","lvl":20,"conf":97,"files":[{"data":"` + bulk + `"}]}`
	insertFeedFixture(t, db, "large", "pkg:pypi/litellm", "1.0", "package.whl", ml)
	rows, err := feedSummarySamples(t.Context(), db, &hopper.FeedQuery{PURLBase: "pkg:pypi/litellm", Limit: 1}, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v error=%v", rows, err)
	}
	if len(rows[0].LitmusResult) > 256 {
		t.Fatalf("summary transferred %d bytes of ML data", len(rows[0].LitmusResult))
	}
}
