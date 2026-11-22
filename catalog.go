package main

// Prism's reads of hopper's verdict schema, through hopper's store package,
// and their mapping onto the views prism renders. Prism reads the database
// directly so its pages never wait on hopper's API, and it never writes it:
// every write (rescans, uploads) goes through the API, and the pool's
// sessions are read-only to the server as well. Where hopper's API answers a
// question, prism asks the same library function the API does
// (hopper.LookupStore for a verdict, hopper.SightingsFromStore for the
// ledger), so a page and an API answer agree.

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultHopperSchema is the schema hopper's verdict tables live in.
const defaultHopperSchema = "verdict"

var (
	// hopperStore is the verdict store. An atomic.Pointer because
	// connectHopperWithRetry may publish it from a background goroutine after
	// a failed first connect; readers take one snapshot with Load.
	hopperStore atomic.Pointer[store.Store]
	// hopperSchema is the schema the store reads (--schema).
	hopperSchema = defaultHopperSchema
)

// openHopperStore connects to hopper's database and returns the store on the
// verdict tables in schema. Sessions are read-only to the server, and JIT is
// off: prism's statements are short index walks a JIT compile only slows.
func openHopperStore(ctx context.Context, dsn, schema string) (*store.Store, *pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("hopper store: %w", err)
	}
	params := cfg.ConnConfig.RuntimeParams
	params["search_path"] = schema
	params["application_name"] = "prism"
	params["default_transaction_read_only"] = "on"
	params["jit"] = "off"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("hopper store: %w", err)
	}
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, pgx.Identifier{schema, "verdicts"}.Sanitize()).Scan(&ok); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("hopper store: %w", err)
	}
	if !ok {
		pool.Close()
		return nil, nil, fmt.Errorf("hopper store: schema %q holds no verdict tables", schema)
	}
	st, err := store.New(pool)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return st, pool, nil
}

// maxMemberStubs bounds the members an archive's page lists. Each is a stub
// (where it sits, what it is, how atomscan judged it) until
// /file/{sha}/members splices in the reports of the few the page shows.
const maxMemberStubs = 10000

// errNotAnalyzed is what a lookup of bytes hopper holds but nothing has
// judged is told; loadParentSample turns it into a pendingAnalysisError.
var errNotAnalyzed = errors.New("not analyzed yet")

// catalogResult reads what the detail page renders for exact bytes: the file,
// the verdict hopper's lookup serves for it, atomscan's report, and the
// archive's members as stubs.
func catalogResult(ctx context.Context, st *store.Store, sha string) (storedResult, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != 32 {
		return storedResult{}, fmt.Errorf("sample %q: %w", sha, store.ErrNotFound)
	}
	s, err := st.Sample(ctx, digest)
	if err != nil {
		return storedResult{}, err
	}
	atom, judged := s.Opinions["atomscan"]
	if !judged {
		return storedResult{Filename: catalogFilename(artifactFilename(s.Provenance), s.Name, s.Version, s.URL, s.Location), CreatedAt: s.CreatedAt},
			errNotAnalyzed
	}
	// The verdict as /v1/lookup serves it: the ledger's word and what the file
	// holds or points at can tighten it. Best-effort here: a failed lookup
	// leaves the page with atomscan's own reading, which it states.
	var raised *hopper.LookupRecord
	if rec, err := hopper.LookupStore(ctx, st, sha, "", ""); err == nil {
		raised = rec
	} else {
		logger.Warn("lookup for the detail page failed; showing atomscan's own verdict", "sha256", sha, "error", err)
	}
	reports, err := st.Reports(ctx, []int64{s.ID})
	if err != nil {
		return storedResult{}, err
	}
	members, truncated, err := st.Members(ctx, s.ID, maxMemberStubs)
	if err != nil {
		return storedResult{}, err
	}
	ids := make([]int64, len(members))
	for i := range members {
		ids[i] = members[i].ID
	}
	opinions, err := st.Opinions(ctx, ids)
	if err != nil {
		return storedResult{}, err
	}
	filename := catalogFilename(artifactFilename(s.Provenance), s.Name, s.Version, s.URL, s.Location)
	level := verdictLevel(atom, raised)
	env, mol, err := buildEnvelope(s, level, reports[s.ID], filename, members, truncated, opinions)
	if err != nil {
		return storedResult{}, err
	}
	res := storedResultFromSample(s, filename, env)
	res.Classification = classificationName(classFromLevel(level))
	res.Formula = mol
	if raised != nil {
		res.RaisedBy = raised.RaisedBy
	}
	return res, nil
}

// verdictLevel is the level the page reads its class from (prism's own
// policy, classFromLevel): the lookup's when it measured one, else one
// standing for the class the lookup or atomscan reached. nil reads hostile.
func verdictLevel(atom store.Opinion, rec *hopper.LookupRecord) *int {
	if rec != nil && rec.FiresAt != nil {
		return rec.FiresAt
	}
	if rec != nil && len(rec.RaisedBy) > 0 {
		return nil // raised to hostile by something with no level of its own
	}
	if atom.FiresAt != nil && classFromLevel(atom.FiresAt) == classIndex(atom.Class) {
		return atom.FiresAt
	}
	return levelForClass(atom.Class)
}

// levelForClass is a level prism's policy reads as class: -1 never fires
// (benign), the suspicious ceiling, and nil (hostile without a level).
func levelForClass(class string) *int {
	switch class {
	case "hostile":
		return nil
	case "suspicious":
		l := SuspiciousCeiling
		return &l
	default:
		l := -1
		return &l
	}
}

// classIndex is prism's integer class (0 benign, 1 suspicious, 2 hostile).
func classIndex(class string) int {
	return max(slices.Index(classificationNames[:], class), 0)
}

// memberLevel is the level a member's own atomscan opinion reads at; -1, no
// statement, when it has none.
func memberLevel(op map[string]store.Opinion) *int {
	atom, ok := op["atomscan"]
	if !ok {
		l := -1
		return &l
	}
	return verdictLevel(atom, nil)
}

// memberRisk orders members by how badly atomscan judged them, then how its
// floor did: the order the page picks the members it shows by
// (envelopeChildSHAs).
func memberRisk(op map[string]store.Opinion) int {
	level := memberLevel(op)
	risk := classFromLevel(level) * 1000000
	switch {
	case level == nil:
		risk += 100000
	case *level >= 0:
		risk += 100000 - min(*level, 99999)
	default:
	}
	switch op["floor"].Class {
	case "hostile":
		risk += 2
	case "suspicious":
		risk++
	default:
	}
	return risk
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// placementKeys are the keys a stub states and a spliced report may not
// override: where the file sits, not what it found.
var placementKeys = []string{"id", "pid", "depth", "dp", "path", "sha", "size", "type", "sid", "rel"}

// buildEnvelope assembles the {ml, llm, raw} envelope the renderer reads,
// from the store: raw is the version 8 file list, the scanned file's own
// report first and then each member as a stub, with sources cited by digest
// rewritten to the list's ids; ml and llm restate atomscan's jurors in the
// shape the page reads them. It returns the report's molecule as well.
func buildEnvelope(sample *store.Sample, level *int, report []byte, filename string, members []store.Member,
	truncated bool, opinions map[int64]map[string]store.Opinion,
) (env []byte, mol string, err error) {
	root := map[string]json.RawMessage{}
	if len(report) > 0 && json.Unmarshal(report, &root) != nil {
		root = map[string]json.RawMessage{} // a report hopper stored but cannot read as one entry
	}
	if raw, ok := root["mol"]; ok {
		_ = json.Unmarshal(raw, &mol) //nolint:errcheck // a molecule that is not a string is none
	}
	sha := hex.EncodeToString(sample.SHA256)
	set(root, "id", 0)
	set(root, "depth", 0)
	set(root, "path", filename)
	set(root, "sha", sha)
	set(root, "size", sample.Size)
	set(root, "type", sample.Type)
	if len(sample.Ident) > 0 && string(sample.Ident) != "null" {
		root["ident"] = sample.Ident
	}
	files := []map[string]json.RawMessage{root}
	entryOf := map[int64]int{sample.ID: 0}
	paths := map[int64]string{sample.ID: filename}
	idOf := map[string]int{sha: 0}
	type mlFile struct {
		L    *int     `json:"lvl"`
		Prob *float64 `json:"prob,omitempty"`
		ID   int      `json:"id"`
	}
	ml := []mlFile{{ID: 0, L: level, Prob: prob(sample.Opinions["ml"])}}
	for i := range members {
		m := &members[i]
		pid, ok := entryOf[m.Parent]
		if !ok {
			continue // its archive fell outside the list
		}
		id := len(files)
		full := paths[m.Parent] + "!!" + m.Path
		mhex := hex.EncodeToString(m.SHA256)
		stub := map[string]json.RawMessage{}
		set(stub, "id", id)
		set(stub, "pid", pid)
		set(stub, "depth", m.Depth)
		set(stub, "path", full)
		set(stub, "sha", mhex)
		set(stub, "size", m.Size)
		set(stub, "type", m.Type)
		set(stub, "sid", m.ID)
		set(stub, "risk", memberRisk(opinions[m.ID]))
		files = append(files, stub)
		if _, seen := entryOf[m.ID]; !seen {
			entryOf[m.ID], paths[m.ID] = id, full
		}
		if _, seen := idOf[mhex]; !seen {
			idOf[mhex] = id
		}
		ml = append(ml, mlFile{ID: id, L: memberLevel(opinions[m.ID]), Prob: prob(opinions[m.ID]["ml"])})
	}
	citeByID(root, idOf)
	raw := map[string]any{"v": 8, "files": files}
	if len(members) > 0 {
		raw["truncated"] = true // the members' reports load with /file/{sha}/members
	}
	if truncated {
		raw["omitted_files"] = maxMemberStubs
	}
	section := map[string]any{"v": "7", "lvl": level, "files": ml}
	if mlOp, ok := sample.Opinions["ml"]; ok {
		var m struct {
			Prob  *float64 `json:"prob"`
			Model string   `json:"model"`
		}
		_ = json.Unmarshal(mlOp.Summary, &m) //nolint:errcheck // a summary that does not parse adds nothing
		section["version"] = m.Model
		if m.Prob != nil {
			section["prob"] = *m.Prob
		}
		section["mods"] = []map[string]int{{"cls": classIndex(mlOp.Class)}}
		section["analyzed_at"] = mlOp.FormedAt.Format(time.RFC3339)
	}
	out := map[string]any{"ml": section, "raw": raw}
	if in, ok := sample.Opinions["llm"]; ok {
		var sum struct {
			Conf   *float64 `json:"conf"`
			Model  string   `json:"model"`
			Reason string   `json:"reason"`
			Error  string   `json:"error"`
		}
		_ = json.Unmarshal(in.Summary, &sum) //nolint:errcheck // a summary that does not parse adds nothing
		out["llm"] = map[string]any{
			"grade": in.Class, "outcome": sample.Opinions["atomscan"].Class, "interpretation": sum.Reason,
			"model": sum.Model, "error": sum.Error, "conf": cmp.Or(deref64(sum.Conf), 0),
		}
	}
	env, err = json.Marshal(out)
	return env, mol, err
}

func deref64(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// prob is the model's probability in an ml opinion, nil without one.
func prob(op store.Opinion) *float64 {
	var m struct {
		Prob *float64 `json:"prob"`
	}
	if len(op.Summary) == 0 || json.Unmarshal(op.Summary, &m) != nil {
		return nil
	}
	return m.Prob
}

// set stores v under key, marshaled.
func set(entry map[string]json.RawMessage, key string, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		return
	}
	entry[key] = raw
}

// citeByID rewrites an entry's sources, which a version 8 report cites by the
// other file's digest, to the ids of the file list the renderer follows. A
// source in a file the list does not hold is dropped: it would otherwise read
// as id 0, the scanned file itself.
func citeByID(entry map[string]json.RawMessage, idOf map[string]int) {
	raw, ok := entry["traits"]
	if !ok {
		return
	}
	var traits []map[string]json.RawMessage
	if json.Unmarshal(raw, &traits) != nil {
		return
	}
	changed := false
	for _, t := range traits {
		var from []map[string]json.RawMessage
		if t["from"] == nil || json.Unmarshal(t["from"], &from) != nil {
			continue
		}
		kept := from[:0]
		for _, src := range from {
			var digest string
			if src["sha256"] == nil || json.Unmarshal(src["sha256"], &digest) != nil {
				kept = append(kept, src)
				continue
			}
			changed = true
			id, ok := idOf[digest]
			if !ok {
				continue
			}
			delete(src, "sha256")
			set(src, "file", id)
			kept = append(kept, src)
		}
		set(t, "from", kept)
	}
	if changed {
		set(entry, "traits", traits)
	}
}

// spliceMembers loads the reports of the wanted members into an envelope's
// stubs and clears the marker that says they are deferred: the member-complete
// view /file/{sha}/members and the JSON export serve. A member's report fills
// its stub without moving it. Stubs past the wanted ones stay stubs.
func spliceMembers(ctx context.Context, st *store.Store, envelope string, wanted []string) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(envelope), &top); err != nil {
		return "", err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(top["raw"], &raw); err != nil {
		return "", err
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(raw["files"], &files); err != nil {
		return "", err
	}
	want := map[string]bool{}
	for _, w := range wanted {
		want[w] = true
	}
	idOf := map[string]int{}
	var ids []int64
	sidOf := map[string]int64{}
	for i, f := range files {
		var sha string
		_ = json.Unmarshal(f["sha"], &sha) //nolint:errcheck // a stub without a digest is never wanted
		if _, seen := idOf[sha]; !seen {
			idOf[sha] = i
		}
		var sid int64
		if i == 0 || !want[sha] || json.Unmarshal(f["sid"], &sid) != nil {
			continue
		}
		if _, seen := sidOf[sha]; !seen {
			sidOf[sha] = sid
			ids = append(ids, sid)
		}
	}
	reports, err := st.Reports(ctx, ids)
	if err != nil {
		return "", err
	}
	for i := 1; i < len(files); i++ {
		var sha string
		_ = json.Unmarshal(files[i]["sha"], &sha) //nolint:errcheck // checked by the lookup below
		report, ok := reports[sidOf[sha]]
		if !ok {
			continue
		}
		var entry map[string]json.RawMessage
		if json.Unmarshal(report, &entry) != nil {
			continue
		}
		for k, v := range entry {
			if !slices.Contains(placementKeys, k) {
				files[i][k] = v
			}
		}
		citeByID(files[i], idOf)
	}
	set(raw, "files", files)
	delete(raw, "truncated")
	set(top, "raw", raw)
	out, err := json.Marshal(top)
	return string(out), err
}

// storedResultFromSample maps what the store holds about a file onto the
// cached record the detail page renders.
func storedResultFromSample(s *store.Sample, filename string, env []byte) storedResult {
	res := storedResult{
		Filename:    filename,
		RawLitmus:   string(env),
		FileType:    s.Type,
		CachedAt:    time.Now().UTC(),
		CreatedAt:   s.CreatedAt,
		SourceURL:   s.URL,
		Ecosystem:   store.EcosystemOf(s.Name, s.Type),
		SizeBytes:   s.Size,
		Version:     s.Version,
		Label:       s.Label,
		LabelSource: s.LabelSource,
		Package:     purlPackageName(s.Name, s.Provenance),
	}
	if strings.HasPrefix(s.Name, "pkg:") {
		res.PURLBase = s.Name
	}
	if u, err := url.Parse(s.URL); err == nil {
		res.SourceDomain = u.Hostname()
	}
	if s.Location != nil {
		res.Source, res.Feed = s.Location.Source, s.Location.Feed
		res.SourceDomain = cmp.Or(res.SourceDomain, s.Location.Feed)
	}
	atom := s.Opinions["atomscan"]
	res.AnalyzedAt, res.TraitsVersion, res.UpdatedAt = atom.FormedAt, atom.Ruleset, atom.FormedAt
	if s.Scan != nil {
		res.AnalyzedAt, res.TraitsVersion = s.Scan.At, s.Scan.Ruleset
	}
	res.RegistryTitle, res.RegistryDesc, res.RegistryDownloads = registryRecord(s.Provenance)
	return res
}

// registryRecord reads the registry record's title, description and download
// count from a provenance document.
func registryRecord(provenance json.RawMessage) (title, desc string, downloads int64) {
	var p struct {
		Registry struct {
			Record struct {
				Downloads   *float64 `json:"downloads_total"`
				Title       string   `json:"title"`
				Description string   `json:"description"`
			} `json:"record"`
		} `json:"registry"`
	}
	if len(provenance) == 0 || json.Unmarshal(provenance, &p) != nil {
		return "", "", 0
	}
	r := p.Registry.Record
	if r.Downloads != nil {
		downloads = int64(*r.Downloads)
	}
	return r.Title, r.Description, downloads
}

// artifactFilename is the name a provenance document says the bytes arrived
// under; empty when it says none.
func artifactFilename(provenance json.RawMessage) string {
	var p struct {
		Artifact struct {
			Filename string `json:"filename"`
		} `json:"artifact"`
	}
	if len(provenance) == 0 || json.Unmarshal(provenance, &p) != nil {
		return ""
	}
	return p.Artifact.Filename
}

// catalogFilename is the name a file is shown under: the one it arrived
// under (arrived), else the last element of where it is held or was fetched
// from, else its release.
func catalogFilename(arrived, name, version, rawURL string, loc *store.Location) string {
	if arrived != "" {
		return arrived
	}
	if loc != nil && loc.Path != "" {
		return path.Base(loc.Path)
	}
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" && u.Path != "/" {
		return path.Base(u.Path)
	}
	if pkg := purlPackageName(name, nil); pkg != "" {
		return strings.TrimSuffix(pkg+"@"+version, "@")
	}
	return ""
}

// purlPackageName is a release's package name: the provenance's when it
// names one, else the package URL's namespace and name ("@expo/log-box").
func purlPackageName(name string, provenance json.RawMessage) string {
	var p struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
	}
	if len(provenance) > 0 && json.Unmarshal(provenance, &p) == nil && p.Package.Name != "" {
		return p.Package.Name
	}
	rest, ok := strings.CutPrefix(name, "pkg:")
	if !ok {
		return ""
	}
	_, rest, _ = strings.Cut(rest, "/")
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	if unescaped, err := url.PathUnescape(rest); err == nil {
		return unescaped
	}
	return rest
}

// classNames maps a criticality filter's integer classes to atomscan's.
func classNames(classes []int) []string {
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		out = append(out, classificationName(c))
	}
	return out
}

// feedRowFromStore maps one row of the store's feed onto prism's.
func feedRowFromStore(r *store.FeedRow, now time.Time) feedRow {
	why, grade, conf := r.LLMWhy, r.LLMClass, 0
	switch {
	case why != "" && r.LLMConf != nil:
		conf = int(*r.LLMConf*100 + 0.5)
	case why == "":
		grade = ""
		level := r.FiresAt
		if level == nil || classFromLevel(level) != classIndex(r.Class) {
			level = levelForClass(r.Class)
		}
		if r.Class != "benign" {
			conf = levelConfidence(level)
		}
	default:
	}
	var probability float64
	if r.MLProb != nil {
		probability = *r.MLProb
	}
	var chips []feedTrait
	if top, err := json.Marshal(r.Top); err == nil {
		chips = parseTopTraits(string(top))
	}
	sha := hex.EncodeToString(r.SHA256)
	var loc *store.Location
	if r.Path != "" {
		loc = &store.Location{Path: r.Path}
	}
	filename := catalogFilename(r.Filename, r.Name, r.Version, r.URL, loc)
	purlBase := ""
	if strings.HasPrefix(r.Name, "pkg:") {
		purlBase = r.Name
	}
	eco := store.EcosystemOf(r.Name, r.Type)
	return feedRow{
		SHA256:         sha,
		SHA256Short:    shortSHA(sha),
		Filename:       filename,
		Classification: r.Class,
		Probability:    probability,
		SuspiciousT:    0.65,
		HostileT:       0.887,
		FileType:       r.Type,
		Source:         r.Source,
		Feed:           r.Feed,
		Ecosystem:      eco,
		EcosystemURL:   ecosystemURL(eco),
		Package:        purlPackageName(r.Name, nil),
		Version:        r.Version,
		PURLBase:       purlBase,
		RegistryTitle:  r.RegistryTitle,
		Desc:           truncDesc(r.RegistryDescription),
		Users:          formatCount(r.RegistryDownloads),
		Downloads:      r.RegistryDownloads,
		Why:            why,
		Conf:           conf,
		TopTraits:      chips,
		LLMGrade:       grade,
		Corroborated:   r.Cited,
		HasURL:         r.URL != "",
		AnalyzedAt:     r.CreatedAt,
		AnalyzedDate:   feedDate(r.CreatedAt, now),
		TimeAgo:        timeAgo(now.Sub(r.CreatedAt)),
	}
}

// parentArchiveFromStore maps an archive that holds childSHA onto the
// backlink the detail page renders.
func parentArchiveFromStore(p *store.Parent, childSHA string) ParentArchive {
	sha := hex.EncodeToString(p.SHA256)
	entry := ParentArchive{
		SHA256:      sha,
		SHA256Short: shortSHA(sha),
		Filename:    catalogFilename(p.Filename, p.Name, p.Version, "", p.Location),
		ChildSHA:    childSHA,
		Path:        p.Path,
		Ecosystem:   store.EcosystemOf(p.Name, p.Type),
		Version:     p.Version,
		Package:     purlPackageName(p.Name, nil),
	}
	if p.Location != nil {
		entry.Feed = p.Location.Feed
	}
	if p.Class != "" {
		level := p.FiresAt
		if level == nil || classFromLevel(level) != classIndex(p.Class) {
			level = levelForClass(p.Class)
		}
		entry.Classification = classificationName(classFromLevel(level))
	}
	if !p.ScannedAt.IsZero() {
		entry.AnalyzedAt = p.ScannedAt.Format("2 Jan 2006 15:04 UTC")
		entry.AnalyzedAgo = timeAgo(time.Since(p.ScannedAt))
	}
	return entry
}

// analyzedAt reports when atomscan last judged exact bytes: their last scan,
// or for a file only seen inside another, when its verdict was formed. Zero
// when hopper holds the bytes but nothing has judged them; store.ErrNotFound
// when it does not hold them.
func analyzedAt(ctx context.Context, st *store.Store, sha string) (time.Time, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != 32 {
		return time.Time{}, store.ErrNotFound
	}
	s, err := st.Sample(ctx, digest)
	if err != nil {
		return time.Time{}, err
	}
	if s.Scan != nil {
		return s.Scan.At, nil
	}
	return s.Opinions["atomscan"].FormedAt, nil
}

// catalogFeed reads one page of the store's feed. A substring search has no
// index to use, so it gets a short deadline: it must not hold the browser for
// a minute.
func catalogFeed(ctx context.Context, st *store.Store, q *store.FeedQuery) ([]store.FeedRow, error) {
	if q.Search != "" && !validSHA256(strings.ToLower(q.Search)) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, feedSearchTimeout)
		defer cancel()
	}
	return st.Feed(ctx, q)
}

// feedSearchTimeout bounds a substring search of the feed.
const feedSearchTimeout = 3 * time.Second

// catalogFeedInWindow reads a feed query, paging when it carries a window. An
// unwindowed query is one page: the row cap is the whole point of the index
// feed, which shows the newest rows and pages in memory. A windowed one is a
// period the caller means to see all of, so it walks the window down — each
// page asking for what is left below the oldest row it has seen — until the
// window empties, the page cap is reached, or a page adds nothing new. Ties on
// the boundary instant are why the next bound is inclusive of the last row and
// why rows are deduped by digest: re-reading one row beats losing the ones
// beside it. truncated reports that the page cap stopped it.
func catalogFeedInWindow(ctx context.Context, st *store.Store, q *store.FeedQuery) (rows []store.FeedRow, truncated bool, err error) {
	if q.Since.IsZero() && q.Until.IsZero() {
		rows, err = catalogFeed(ctx, st, q)
		return rows, false, err
	}
	q.Limit = feedWindowPageSize
	seen := make(map[string]bool, feedWindowPageSize)
	for range feedWindowPages {
		page, err := catalogFeed(ctx, st, q)
		if err != nil {
			return nil, false, err
		}
		added := 0
		for i := range page {
			key := string(page[i].SHA256)
			if seen[key] {
				continue
			}
			seen[key] = true
			rows = append(rows, page[i])
			added++
		}
		if len(page) < q.Limit || added == 0 {
			return rows, false, nil
		}
		q.Until = page[len(page)-1].CreatedAt.Add(time.Microsecond)
	}
	return rows, true, nil
}

// resolvePackageSearch returns the candidate package identities some sample
// is filed under. Resolve before applying verdict/version filters so an
// existing package with no matching releases stays empty instead of falling
// through to unrelated filenames. Every matching ecosystem is retained.
func resolvePackageSearch(ctx context.Context, st *store.Store, candidates []string) ([]string, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	spelled := make([]string, len(candidates))
	for i, c := range candidates {
		spelled[i] = store.NameOf(c) // names are spelled as the store spells them
	}
	slices.Sort(spelled)
	named, err := st.Named(ctx, slices.Compact(spelled))
	if err != nil {
		return nil, fmt.Errorf("resolve package search: %w", err)
	}
	return named, nil
}
