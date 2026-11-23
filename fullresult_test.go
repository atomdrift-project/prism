package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// uploadEnvelope is the cached envelope's parts the tests read.
type uploadEnvelope struct {
	ML  litmusMlResponse  `json:"ml"`
	LLM llmInterpretation `json:"llm"`
	Raw struct {
		cleaveReport

		Truncated bool `json:"truncated"`
	} `json:"raw"`
}

// decodeUploadEnvelope reads a cached result's envelope, and its file list as
// raw objects for keys the typed view drops.
func decodeUploadEnvelope(t *testing.T, res *storedResult) (env uploadEnvelope, files []map[string]json.RawMessage) {
	t.Helper()
	if err := json.Unmarshal([]byte(res.RawLitmus), &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	var loose struct {
		Raw struct {
			Files []map[string]json.RawMessage `json:"files"`
		} `json:"raw"`
	}
	if err := json.Unmarshal([]byte(res.RawLitmus), &loose); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return env, loose.Raw.Files
}

// fullBody is the full result in a stream Beamline answered with: the lines
// from its v8 header on.
func fullBody(t *testing.T, path string) []byte {
	t.Helper()
	stream, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(stream, []byte(`{"v":8,`))
	if at < 0 {
		t.Fatalf("%s holds no full result", path)
	}
	return stream[at:]
}

// TestStoredResultFromFullZip maps a full result Beamline answered a real
// zip upload with: the archive and its two members, every report inline.
func TestStoredResultFromFullZip(t *testing.T) {
	const sha = "6179b302ab3c992e48daafba88915bf86c76b40e41f9e719a67f34007eb0359f"
	res, err := storedResultFromFull(fullBody(t, "testdata/beamline-full-zip.ndjson"), "fixture.zip", strings.ToUpper(sha))
	if err != nil {
		t.Fatal(err)
	}
	if res.Filename != "fixture.zip" || res.Classification != "benign" || res.FileType != "zip" || res.SizeBytes != 310 ||
		res.TraitsVersion != "3121b" || res.AnalyzedAt.Format("2006-01-02T15:04:05Z") != "2026-11-23T15:15:59Z" {
		t.Errorf("result %+v", res)
	}
	if membersDeferred(res.RawLitmus) {
		t.Error("an upload's members came with their reports; none may be deferred to hopper")
	}
	env, loose := decodeUploadEnvelope(t, &res)
	if env.ML.verdictClass() != 0 || env.ML.L == nil || *env.ML.L != -1 {
		t.Errorf("ml %+v, want benign at -1", env.ML)
	}
	files := env.Raw.Files
	if len(files) != 3 || files[0].SHA256 != sha || files[0].Path != "fixture.zip" ||
		files[1].Path != "fixture.zip!!install.sh" || files[1].FileType != "shell" || files[1].Parent == nil || *files[1].Parent != 0 ||
		files[2].Path != "fixture.zip!!tool.py" || files[2].FileType != "python" {
		t.Fatalf("files %+v", files)
	}
	for i, f := range loose {
		if _, ok := f["sid"]; ok {
			t.Errorf("file %d carries a store id; an upload has none", i)
		}
		if _, ok := f["facts"]; !ok {
			t.Errorf("file %d has no facts; its report was not inlined", i)
		}
	}
	data := prepareResultData(res.Filename, sha, &res)
	if data.RiskLevel != "benign" || data.DeferredMembers {
		t.Errorf("rendered risk %q, deferred members %v", data.RiskLevel, data.DeferredMembers)
	}
}

// TestStoredResultFromFullShell maps the full result of a lone file.
func TestStoredResultFromFullShell(t *testing.T) {
	const sha = "0638f184fda2b090f38a8437b723233c2174ffac5085c59270f80dfae70f332f"
	res, err := storedResultFromFull(fullBody(t, "testdata/beamline-full-shell.ndjson"), "probe.sh", sha)
	if err != nil {
		t.Fatal(err)
	}
	if res.Classification != "benign" || res.FileType != "shell" || res.SizeBytes != 49 {
		t.Errorf("result %+v", res)
	}
	env, _ := decodeUploadEnvelope(t, &res)
	if len(env.Raw.Files) != 1 || env.Raw.Files[0].Path != "probe.sh" || env.Raw.Truncated {
		t.Errorf("files %+v truncated %v", env.Raw.Files, env.Raw.Truncated)
	}
}

// TestStoredResultFromFullHostile maps the result catalog_test files in the
// store, so an uploaded copy of the package reads as the stored one does.
func TestStoredResultFromFullHostile(t *testing.T) {
	pkg, script, files, reports := evilResult()
	// A juror hopper does not store is still part of what scan sends; it is no
	// reason to refuse the upload.
	files[0]["uplink"] = map[string]any{"class": "hostile", "fires_at": 3, "engine": "3.0.0"}
	res, err := storedResultFromFull(resultBody(t, files, reports), "evil-1.0.0.tgz", pkg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Classification != "hostile" || res.Formula != "H(Os)" || res.Ecosystem != "javascript" || res.TraitsVersion != "r1" {
		t.Errorf("result %+v", res)
	}
	env, _ := decodeUploadEnvelope(t, &res)
	if env.ML.verdictClass() != 2 || env.ML.L == nil || *env.ML.L != 12 || env.ML.Probability != 0.97 {
		t.Errorf("ml %+v, want hostile at 12 with the model's probability", env.ML)
	}
	if env.LLM.Interpretation != "Downloads and runs a binary at install." || env.LLM.Grade != "hostile" || env.LLM.Outcome != "hostile" {
		t.Errorf("llm %+v", env.LLM)
	}
	got := env.Raw.Files
	if len(got) != 2 || got[1].SHA256 != script || got[1].Path != "evil-1.0.0.tgz!!package/install.js" {
		t.Fatalf("files %+v", got)
	}
	if f := got[0].Findings; len(f) != 1 || len(f[0].From) != 1 || f[0].From[0].File != 1 {
		t.Errorf("root findings %+v, want the source cited by digest rewritten to the member's id", f)
	}
	if m := got[1]; len(m.Findings) != 1 || m.Findings[0].ID != "b::fetch-exec" || m.Formula != "Os" {
		t.Errorf("member %+v, want its report inline", m)
	}
	data := prepareResultData(res.Filename, pkg, &res)
	if data.RiskLevel != "hostile" || data.FindingCount == "0" {
		t.Errorf("rendered risk %q with %s findings", data.RiskLevel, data.FindingCount)
	}
}

// TestStoredResultFromFullRefuses covers bodies that must fail the upload
// rather than render: each would otherwise show a wrong or empty verdict.
func TestStoredResultFromFullRefuses(t *testing.T) {
	pkg, _, files, reports := evilResult()
	body := string(resultBody(t, files, reports))
	lines := strings.SplitAfter(body, "\n")
	for _, tc := range []struct {
		name, body, sha, want string
	}{
		{"other bytes", body, hexDigest("something else"), "not the uploaded"},
		{"report swapped", lines[0] + lines[1] + lines[2] + lines[4] + lines[3], pkg, "report hashes to"},
		{"report missing", lines[0] + lines[1] + lines[2] + lines[3], pkg, "report missing"},
		{"line after reports", body + `{"extra":true}` + "\n", pkg, "after the last report"},
		{"old version", strings.Replace(body, `{"v":8,`, `{"v":7,`, 1), pkg, "version 7"},
		{"too few files", strings.Replace(body, `"files":2}`, `"files":9}`, 1), pkg, "9 files"},
		{"empty", "", pkg, "empty body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if res, err := storedResultFromFull([]byte(tc.body), "evil-1.0.0.tgz", tc.sha); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("result %+v, error %v; want an error mentioning %q", res.Classification, err, tc.want)
			}
		})
	}
}

// TestStoredResultFromFullUnconcluded refuses an artifact whose verdict
// reached no class: rendered, it would read benign.
func TestStoredResultFromFullUnconcluded(t *testing.T) {
	pkg, _, files, reports := evilResult()
	files[0]["verdict"] = map[string]any{"outcome": "timeout"}
	delete(files[0], "ml")
	delete(files[0], "floor")
	delete(files[0], "llm")
	if _, err := storedResultFromFull(resultBody(t, files, reports), "evil-1.0.0.tgz", pkg); err == nil ||
		!strings.Contains(err.Error(), "not a conclusion") {
		t.Errorf("error %v, want an unconcluded verdict refused", err)
	}
}
