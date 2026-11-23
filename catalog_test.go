package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/scanresult"
	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestStore creates hopper's verdict schema in a fresh schema of a
// disposable database and publishes it as the store prism reads, opened the
// way prism opens it (read-only sessions). It returns a second, writable
// store on the same schema to file fixtures through, as hopper would.
//
//	PRISM_TEST_PG_DSN="$(../hopper/scripts/test-pg.sh)" go test .
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	logger = slog.New(slog.DiscardHandler)
	dsn := strings.TrimSpace(os.Getenv("PRISM_TEST_PG_DSN"))
	if dsn == "" {
		t.Skip("PRISM_TEST_PG_DSN not set (a disposable Postgres database)")
	}
	if strings.Contains(dsn, "hopper-db") || strings.Contains(dsn, "hopper-replica") {
		t.Fatal("PRISM_TEST_PG_DSN names a production host; these tests write data")
	}
	ctx := t.Context()
	schema := fmt.Sprintf("prism_%d", time.Now().UnixNano())
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		pool.Close()
	})
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, store.Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	writer, err := store.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	reader, readPool, err := openHopperStore(ctx, dsn, schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readPool.Close)
	hopperStore.Store(reader)
	t.Cleanup(func() { hopperStore.Store(nil) })
	return writer
}

func digest(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func hexDigest(s string) string { return hex.EncodeToString(digest(s)) }

// resultBody is a version 8 result: a header, one line per file, then the
// reports in file order.
func resultBody(t *testing.T, files []map[string]any, reports []string) []byte {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"v":8,"scan":{"engine":"3.0.0","ruleset":"r1","level":25,"worker":"w1","at":"2026-11-12T15:00:00Z","ms":40},"files":%d}`+"\n", len(files))
	for _, f := range files {
		line, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(append(line, '\n'))
	}
	for _, r := range reports {
		b.WriteString(r + "\n")
	}
	return b.Bytes()
}

// fileResult writes a version 8 result to the store.
func fileResult(t *testing.T, w *store.Store, files []map[string]any, reports []string) {
	t.Helper()
	decoded, err := scanresult.Decode(resultBody(t, files, reports))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := w.Write(t.Context(), decoded); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sumOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// evilPackage files an npm release holding an install script (evilResult).
func evilPackage(t *testing.T, w *store.Store) (pkg, script string) {
	t.Helper()
	mtime := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	if _, err := w.Ingest(t.Context(), []store.Arrival{{
		SHA256: digest("package bytes"), Size: 4000, Path: "bad/npm/evil-1.0.0.tgz", Source: "forager", Feed: "npmjs.org",
		Name: "pkg:npm/evil", Version: "1.0.0", URL: "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz", Mtime: &mtime,
		Provenance: []byte(`{"artifact":{"filename":"evil-1.0.0.tgz"},"registry":{"record":{"title":"Evil","downloads_total":42}}}`),
	}}, store.QueueNew); err != nil {
		t.Fatal(err)
	}
	pkg, script, files, reports := evilResult()
	fileResult(t, w, files, reports)
	return pkg, script
}

// evilResult is an npm release holding an install script, judged as a worker
// would judge it: the package hostile through its script, which a trait of
// the package's report cites by digest.
func evilResult() (pkg, script string, files []map[string]any, reports []string) {
	pkg, script = hexDigest("package bytes"), hexDigest("script bytes")
	reports = []string{
		`{"mol":"H(Os)","traits":[{"id":"b::fetch-exec","crit":5,"desc":"fetches and runs","from":[{"sha256":"` + script + `","line":3}]}]}`,
		`{"mol":"Os","traits":[{"id":"b::fetch-exec","crit":5,"desc":"fetches and runs"}]}`,
	}
	files = []map[string]any{
		{
			"sha256": pkg, "size": 4000, "type": "npm", "report": sumOf(reports[0]),
			"verdict": map[string]any{
				"outcome": "ok", "class": "hostile", "fires_at": 12, "reason": "Install script fetches and runs a binary.",
				"top": []map[string]any{{"id": "b::fetch-exec", "crit": 5}},
			},
			"ml":       map[string]any{"class": "hostile", "fires_at": 12, "prob": 0.97, "model": "v18"},
			"floor":    map[string]any{"class": "hostile", "fires_at": 12, "hostile": 1},
			"llm":      map[string]any{"class": "hostile", "conf": 0.9, "model": "m", "reason": "Downloads and runs a binary at install."},
			"contents": map[string]any{"children": []int{1}, "paths": []string{"package/install.js"}},
		},
		{
			"sha256": script, "size": 300, "type": "javascript", "report": sumOf(reports[1]),
			"verdict": map[string]any{"outcome": "ok", "class": "hostile", "fires_at": 12},
			"floor":   map[string]any{"class": "hostile", "fires_at": 12, "hostile": 1},
		},
	}
	return pkg, script, files, reports
}

func TestCatalogResult(t *testing.T) {
	w := newTestStore(t)
	pkg, script := evilPackage(t, w)
	ctx := t.Context()

	res, err := loadParentSample(ctx, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Filename != "evil-1.0.0.tgz" || res.PURLBase != "pkg:npm/evil" || res.Package != "evil" || res.Version != "1.0.0" ||
		res.Ecosystem != "javascript" || res.Classification != "hostile" || res.Formula != "H(Os)" || res.Feed != "npmjs.org" ||
		res.Source != "forager" || res.RegistryTitle != "Evil" || res.RegistryDownloads != 42 || res.SizeBytes != 4000 ||
		res.TraitsVersion != "r1" || res.AnalyzedAt.IsZero() {
		t.Errorf("result %+v", res)
	}
	if !membersDeferred(res.RawLitmus) {
		t.Fatal("an archive's first paint defers its members' reports")
	}
	var env struct {
		ML  litmusMlResponse  `json:"ml"`
		LLM llmInterpretation `json:"llm"`
		Raw cleaveReport      `json:"raw"`
	}
	if err := json.Unmarshal([]byte(res.RawLitmus), &env); err != nil {
		t.Fatal(err)
	}
	if env.ML.verdictClass() != 2 || env.ML.L == nil || *env.ML.L != 12 || env.ML.Probability != 0.97 {
		t.Errorf("ml %+v, want hostile at 12 with the model's probability", env.ML)
	}
	if env.LLM.Interpretation != "Downloads and runs a binary at install." || env.LLM.Grade != "hostile" {
		t.Errorf("llm %+v", env.LLM)
	}
	files := env.Raw.Files
	if len(files) != 2 || files[0].SHA256 != pkg || files[0].Path != "evil-1.0.0.tgz" || files[1].SHA256 != script ||
		files[1].Parent == nil || *files[1].Parent != 0 || files[1].Path != "evil-1.0.0.tgz!!package/install.js" {
		t.Fatalf("files %+v", files)
	}
	if f := files[0].Findings; len(f) != 1 || len(f[0].From) != 1 || f[0].From[0].File != 1 || f[0].From[0].Line == nil {
		t.Errorf("root findings %+v, want the source cited by digest rewritten to the member's id", f)
	}
	if len(files[1].Findings) != 0 {
		t.Errorf("a member is a stub on first paint, got %+v", files[1].Findings)
	}

	enriched, err := enrichMembers(ctx, pkg, res.RawLitmus)
	if err != nil {
		t.Fatal(err)
	}
	if membersDeferred(enriched) {
		t.Error("the enriched envelope still says its members are deferred")
	}
	res.RawLitmus = enriched
	if err := json.Unmarshal([]byte(enriched), &env); err != nil {
		t.Fatal(err)
	}
	if m := env.Raw.Files[1]; len(m.Findings) != 1 || m.Findings[0].ID != "b::fetch-exec" || m.SHA256 != script || m.Formula != "Os" {
		t.Errorf("member after splicing %+v", m)
	}
	data := prepareResultData(res.Filename, pkg, &res)
	if data.RiskLevel != "hostile" || data.FindingCount == "0" {
		t.Errorf("rendered risk %q with %s findings", data.RiskLevel, data.FindingCount)
	}

	parents := lookupParentArchivesFromHopper(ctx, script, logger)
	if len(parents) != 1 || parents[0].SHA256 != pkg || parents[0].Path != "package/install.js" ||
		parents[0].Classification != "hostile" || parents[0].Filename != "evil-1.0.0.tgz" || !parents[0].containsChild() {
		t.Errorf("parents %+v", parents)
	}
	if at, err := analyzedAt(ctx, hopperStore.Load(), pkg); err != nil || at.IsZero() {
		t.Errorf("analyzed at %v, %v", at, err)
	}
}

func TestCatalogNotFoundAndPending(t *testing.T) {
	w := newTestStore(t)
	ctx := t.Context()
	if _, err := loadParentSample(ctx, hexDigest("never seen")); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown bytes: %v, want store.ErrNotFound", err)
	}
	if _, err := w.Ingest(ctx, []store.Arrival{{SHA256: digest("waiting"), Size: 10, Path: "incoming/waiting.bin"}}, store.QueueNew); err != nil {
		t.Fatal(err)
	}
	_, err := loadParentSample(ctx, hexDigest("waiting"))
	if pending, ok := errors.AsType[*pendingAnalysisError](err); !ok || pending.Filename != "waiting.bin" {
		t.Errorf("unjudged bytes: %v, want a pending analysis named waiting.bin", err)
	}
	if at, err := analyzedAt(ctx, hopperStore.Load(), hexDigest("waiting")); err != nil || !at.IsZero() {
		t.Errorf("analyzed at %v, %v, want held and never judged", at, err)
	}
}

func TestCatalogFeed(t *testing.T) {
	w := newTestStore(t)
	pkg, _ := evilPackage(t, w)
	ctx := t.Context()
	st := hopperStore.Load()

	names, err := resolvePackageSearch(ctx, st, packageSearchPURLs("evil", nil, nil))
	if err != nil || !slices.Equal(names, []string{"pkg:npm/evil"}) {
		t.Fatalf("package search %q %v", names, err)
	}
	rows, truncated, err := catalogFeedInWindow(ctx, st, &store.FeedQuery{Names: names, TopLevel: true, Limit: 10})
	if err != nil || truncated || len(rows) != 1 {
		t.Fatalf("feed %+v %v %v", rows, truncated, err)
	}
	row := feedRowFromStore(&rows[0], time.Now())
	if row.SHA256 != pkg || row.Classification != "hostile" || row.Filename != "evil-1.0.0.tgz" || row.Ecosystem != "javascript" ||
		row.Package != "evil" || row.PURLBase != "pkg:npm/evil" || row.Why != "Downloads and runs a binary at install." ||
		row.Conf != 90 || row.LLMGrade != "hostile" || row.Probability != 0.97 || row.Feed != "npmjs.org" ||
		row.RegistryTitle != "Evil" || row.Downloads != 42 || len(row.TopTraits) != 1 {
		t.Errorf("feed row %+v", row)
	}
	windowed, _, err := catalogFeedInWindow(ctx, st, &store.FeedQuery{Since: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)})
	if err != nil || len(windowed) != 1 {
		t.Errorf("windowed feed %d rows, %v", len(windowed), err)
	}
	if sha := soleSampleByPURL(ctx, "pkg:npm/evil", "1.0.0"); sha != pkg {
		t.Errorf("sole sample %q, want the package", sha)
	}
	if n, top, err := queryExactTotal(ctx); err != nil || n != 2 || top == 0 {
		t.Errorf("total %d (top id %d), %v: the package and its member", n, top, err)
	}
}

// Malware lists a hostile file only once it is labeled bad; until then it is
// Review's.
func TestHostileListsSplitOnLabel(t *testing.T) {
	w := newTestStore(t)
	pkg, _ := evilPackage(t, w)
	ctx := t.Context()
	saved := feedDropdownCache
	feedDropdownCache = openNullCache[feedDropdowns]("test feed dropdowns")
	t.Cleanup(func() { feedDropdownCache = saved })

	list := func(name string) []string {
		t.Helper()
		args := hostileListArgs(name, false)
		fetch, err := loadFeedRowsFromHopper(ctx, &args)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var shas []string
		for i := range fetch.rows {
			shas = append(shas, fetch.rows[i].SHA256)
		}
		return shas
	}
	if got := list(malwareList); len(got) != 0 {
		t.Errorf("malware lists an unlabeled file: %q", got)
	}
	if got := list(reviewList); !slices.Equal(got, []string{pkg}) {
		t.Errorf("review = %q, want the unlabeled package", got)
	}

	if _, err := w.Ingest(ctx, []store.Arrival{{
		SHA256: digest("package bytes"), Size: 4000, Path: "bad/npm/evil-1.0.0.tgz", Label: "bad", LabelSource: "marker",
	}}, store.QueueNew); err != nil {
		t.Fatal(err)
	}
	if got := list(malwareList); !slices.Equal(got, []string{pkg}) {
		t.Errorf("malware = %q, want the package once labeled bad", got)
	}
	if got := list(reviewList); len(got) != 0 {
		t.Errorf("review lists a file labeled bad: %q", got)
	}
}

// Prism's sessions are read-only to the server, so a write through its store
// fails; and a schema without hopper's tables is refused at open.
func TestCatalogIsReadOnly(t *testing.T) {
	newTestStore(t)
	ctx := t.Context()
	_, err := hopperStore.Load().Ingest(ctx, []store.Arrival{{SHA256: digest("x"), Size: 10, Path: "incoming/x"}}, store.QueueNew)
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("a write through prism's store: %v, want a read-only transaction refusing it", err)
	}
	if _, pool, err := openHopperStore(ctx, os.Getenv("PRISM_TEST_PG_DSN"), "public"); err == nil {
		pool.Close()
		t.Error("opened a schema with no verdict tables")
	}
}

func TestVerdictLevel(t *testing.T) {
	at := func(n int) *int { return &n }
	raised := &hopper.LookupRecord{RaisedBy: []hopper.LookupRaiser{{Kind: "member"}}}
	for _, c := range []struct {
		name string
		atom store.Opinion
		rec  *hopper.LookupRecord
		want *int
	}{
		{"the lookup's level", store.Opinion{Class: "benign", FiresAt: at(-1)}, &hopper.LookupRecord{FiresAt: at(3)}, at(3)},
		{"raised with no level reads hostile", store.Opinion{Class: "benign", FiresAt: at(-1)}, raised, nil},
		{"atomscan's own level when it agrees with its class", store.Opinion{Class: "suspicious", FiresAt: at(400)}, nil, at(400)},
		{"a class with no level", store.Opinion{Class: "suspicious"}, nil, at(suspiciousCeiling(CriticalLevel))},
		{"a level the class disowns", store.Opinion{Class: "benign", FiresAt: at(3)}, nil, at(-1)},
		{"hostile by its floor", store.Opinion{Class: "hostile", FiresAt: at(-1)}, nil, nil},
	} {
		got := verdictLevel(c.atom, c.rec)
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Errorf("%s: %v, want %v", c.name, deref(got), deref(c.want))
		}
	}
}

func TestCiteByID(t *testing.T) {
	entry := map[string]json.RawMessage{"traits": json.RawMessage(`[
		{"id":"a","from":[{"sha256":"aa","line":2},{"sha256":"zz"}]},
		{"id":"b"}]`)}
	citeByID(entry, map[string]int{"aa": 4})
	var traits []struct {
		From []map[string]any `json:"from"`
		ID   string           `json:"id"`
	}
	if err := json.Unmarshal(entry["traits"], &traits); err != nil {
		t.Fatal(err)
	}
	if len(traits) != 2 || len(traits[0].From) != 1 || traits[0].From[0]["file"] != float64(4) || traits[0].From[0]["line"] != float64(2) ||
		traits[0].From[0]["sha256"] != nil {
		t.Errorf("traits %+v, want aa cited as id 4 and zz, which the list does not hold, dropped", traits)
	}
}

func TestPURLPackageName(t *testing.T) {
	for name, want := range map[string]string{
		"pkg:npm/%40expo/log-box-utils": "@expo/log-box-utils",
		"pkg:pypi/requests":             "requests",
		"pkg:maven/org.example/lib?x=1": "org.example/lib",
		"https://example.com/x.zip":     "",
		"":                              "",
	} {
		if got := purlPackageName(name, nil); got != want {
			t.Errorf("purlPackageName(%q) = %q, want %q", name, got, want)
		}
	}
	if got := purlPackageName("pkg:npm/x", json.RawMessage(`{"package":{"name":"real-name"}}`)); got != "real-name" {
		t.Errorf("provenance's name: %q", got)
	}
}
