package main

// An upload's result arrives as scan's full result: the version 8 body a
// worker uploads to hopper, streamed back by /v1/analyze?full=1 (scan's
// docs/JSON.md). It is mapped onto the same envelope catalogResult builds from
// the store, through buildEnvelope, so an upload's page and the stored file's
// page render alike.
//
// hopper's scanresult.Decode reads the same body but refuses any field it does
// not know, as a store must. scan adds fields a page can ignore (an `uplink`
// juror on the artifact's line), so prism reads the body leniently: a field it
// does not use is not a reason to fail an upload.

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper/store"
)

// fullResultVersion is the full result body version prism reads.
const fullResultVersion = 8

type fullHeader struct {
	Scan struct {
		At      time.Time `json:"at"`
		Ruleset string    `json:"ruleset"`
	} `json:"scan"`
	V     int `json:"v"`
	Files int `json:"files"`
}

// fullFile is one file line of a full result.
type fullFile struct {
	Contents *struct {
		Children []int    `json:"children"`
		Paths    []string `json:"paths"`
	} `json:"contents"`
	SHA256  string          `json:"sha256"`
	Type    string          `json:"type"`
	Report  string          `json:"report"` // sha256 of its report line
	Verdict json.RawMessage `json:"verdict"`
	ML      json.RawMessage `json:"ml"`
	Floor   json.RawMessage `json:"floor"`
	LLM     json.RawMessage `json:"llm"`
	Ident   json.RawMessage `json:"ident"`
	report  []byte          // the report line; nil without one
	Size    int64           `json:"size"`
}

// parseFullResult splits a full result into its header and files, each file
// holding its report line. The shape is checked as hopper checks it: a
// report that does not hash to the digest its file names, a missing one, or
// a line past the last report means the body was misread or cut short.
func parseFullResult(body []byte) (fullHeader, []fullFile, error) {
	var head fullHeader
	var lines [][]byte
	for line := range bytes.Lines(body) {
		if line = bytes.TrimSpace(line); len(line) > 0 {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return head, nil, errors.New("full result: empty body")
	}
	if err := json.Unmarshal(lines[0], &head); err != nil {
		return head, nil, fmt.Errorf("full result header: %w", err)
	}
	if head.V != fullResultVersion {
		return head, nil, fmt.Errorf("full result header: version %d, want %d", head.V, fullResultVersion)
	}
	if head.Files < 1 || head.Files > len(lines)-1 {
		return head, nil, fmt.Errorf("full result header: %d files, but %d lines follow it", head.Files, len(lines)-1)
	}
	files := make([]fullFile, head.Files)
	for i := range files {
		f := &files[i]
		if err := json.Unmarshal(lines[1+i], f); err != nil {
			return head, nil, fmt.Errorf("full result file %d: %w", i, err)
		}
		f.SHA256 = strings.ToLower(f.SHA256)
		if !validSHA256(f.SHA256) {
			return head, nil, fmt.Errorf("full result file %d: sha256 %.80q is not a digest", i, f.SHA256)
		}
	}
	next := 1 + head.Files
	for i := range files {
		f := &files[i]
		if f.Report == "" {
			continue
		}
		if next == len(lines) {
			return head, nil, fmt.Errorf("full result file %d: report missing", i)
		}
		sum := sha256.Sum256(lines[next])
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, f.Report) {
			return head, nil, fmt.Errorf("full result file %d: report hashes to %s, the file line says %.80s", i, got, f.Report)
		}
		f.report = lines[next]
		next++
	}
	if next != len(lines) {
		return head, nil, fmt.Errorf("full result: %d lines after the last report", len(lines)-next)
	}
	return head, files, nil
}

// fullOpinions maps a file line's verdict and jurors onto the store's
// opinions, as hopper stores them: the verdict is atomscan's, and each object
// is kept whole as the summary the envelope reads probabilities and readings
// from. An absent or null object is no statement.
func fullOpinions(f *fullFile, at time.Time, ruleset string) map[string]store.Opinion {
	ops := map[string]store.Opinion{}
	for name, obj := range map[string]json.RawMessage{"atomscan": f.Verdict, "ml": f.ML, "floor": f.Floor, "llm": f.LLM} {
		var o struct {
			FiresAt *int   `json:"fires_at"`
			Outcome string `json:"outcome"`
			Class   string `json:"class"`
		}
		if len(obj) == 0 || string(obj) == "null" || json.Unmarshal(obj, &o) != nil {
			continue
		}
		ops[name] = store.Opinion{
			FormedAt: at, FiresAt: o.FiresAt, Outcome: cmp.Or(o.Outcome, "ok"),
			Class: o.Class, Ruleset: ruleset, Summary: obj,
		}
	}
	return ops
}

// storedResultFromFull maps an upload's full result onto the cached record the
// detail page renders. sha is the digest of the uploaded bytes, which the
// result must be about.
func storedResultFromFull(body []byte, filename, sha string) (storedResult, error) {
	head, files, err := parseFullResult(body)
	if err != nil {
		return storedResult{}, err
	}
	art := &files[0]
	if !strings.EqualFold(art.SHA256, sha) {
		return storedResult{}, fmt.Errorf("full result is about %s, not the uploaded %s", art.SHA256, sha)
	}
	at := head.Scan.At.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ops := fullOpinions(art, at, head.Scan.Ruleset)
	// A full result is only written for an analysis that concluded, so a
	// verdict without a class is a misread body, never a benign file.
	atom, judged := ops["atomscan"]
	if !judged || atom.Outcome != "ok" || !slices.Contains(classificationNames[:], atom.Class) {
		return storedResult{}, fmt.Errorf("full result: artifact verdict %.200s is not a conclusion", art.Verdict)
	}

	// The members as the store lists them: breadth first from the artifact,
	// each container's in the order its contents give them. A file id is its
	// line's index, the artifact's 0. A container is walked once, so a body
	// that nests a file inside itself cannot loop.
	var members []store.Member
	opinions := map[int64]map[string]store.Opinion{}
	reports := map[string][]byte{}
	depth := make([]int, len(files))
	walked := make([]bool, len(files))
	walked[0] = true
	truncated := false
	for queue := []int{0}; len(queue) > 0 && !truncated; queue = queue[1:] {
		p := queue[0]
		c := files[p].Contents
		if c == nil {
			continue
		}
		for k, child := range c.Children {
			if child <= 0 || child >= len(files) || k >= len(c.Paths) {
				continue // not another file of this result
			}
			if len(members) == maxMemberStubs {
				truncated = true
				break
			}
			f := &files[child]
			digest, _ := hex.DecodeString(f.SHA256) //nolint:errcheck // validated by parseFullResult
			members = append(members, store.Member{
				Path: c.Paths[k], Type: f.Type, SHA256: digest, ID: int64(child), Parent: int64(p), Size: f.Size, Depth: depth[p] + 1,
			})
			opinions[int64(child)] = fullOpinions(f, at, head.Scan.Ruleset)
			if f.report != nil {
				reports[f.SHA256] = f.report
			}
			if !walked[child] {
				walked[child], depth[child] = true, depth[p]+1
				queue = append(queue, child)
			}
		}
	}

	digest, _ := hex.DecodeString(art.SHA256) //nolint:errcheck // validated by parseFullResult
	sample := store.Sample{SHA256: digest, Size: art.Size, Type: art.Type, Ident: art.Ident, Opinions: ops}
	level := verdictLevel(atom, nil)
	env, mol, err := buildEnvelope(&sample, level, art.report, filename, members, truncated, opinions)
	if err != nil {
		return storedResult{}, fmt.Errorf("full result envelope: %w", err)
	}
	if env, err = inlineReports(env, reports); err != nil {
		return storedResult{}, fmt.Errorf("full result envelope: %w", err)
	}
	now := time.Now().UTC()
	return storedResult{
		Filename:       filename,
		RawLitmus:      string(env),
		Classification: classificationName(classFromLevel(level)),
		Formula:        mol,
		FileType:       art.Type,
		Ecosystem:      store.EcosystemOf("", art.Type),
		TraitsVersion:  head.Scan.Ruleset,
		CachedAt:       now,
		CreatedAt:      now,
		AnalyzedAt:     at,
		UpdatedAt:      at,
		SizeBytes:      art.Size,
	}, nil
}

// inlineReports fills each member stub of env with its report, by digest. An
// upload's members arrive with their reports and have no store id to load
// them by later, so the stubs lose their sid and the envelope its marker
// deferring them to /file/{sha}/members.
func inlineReports(env []byte, reports map[string][]byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(env, &top); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(top["raw"], &raw); err != nil {
		return nil, err
	}
	var files []map[string]json.RawMessage
	if err := json.Unmarshal(raw["files"], &files); err != nil {
		return nil, err
	}
	shas := make([]string, len(files))
	idOf := map[string]int{}
	for i, f := range files {
		_ = json.Unmarshal(f["sha"], &shas[i]) //nolint:errcheck // a stub without a digest has no report to take
		if _, seen := idOf[shas[i]]; !seen {
			idOf[shas[i]] = i
		}
	}
	for i := 1; i < len(files); i++ {
		delete(files[i], "sid")
		if report, ok := reports[shas[i]]; ok {
			fillStub(files[i], report, idOf)
		}
	}
	set(raw, "files", files)
	delete(raw, "truncated")
	set(top, "raw", raw)
	return json.Marshal(top)
}
