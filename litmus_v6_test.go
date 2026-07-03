package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestLitmusMlResponseV6Verdict covers the collapsed v=6 envelope through the
// consumer-side verdict path: `class` and `threshold` are gone from the wire,
// replaced by the single `l` verdict-and-level marker both at the top level
// and inside fs[]. Unlike TestLitmusMlResponseV6 in litmus_v5_test.go (which
// exercises the envelopeClass 0/2 mapping), this asserts the classFromLevel
// policy. Boundary levels are derived from CriticalLevel/SuspiciousCeiling so
// the cases track the operating point instead of hardcoding it.
func TestLitmusMlResponseV6Verdict(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantClass int  // prism's derived verdict class
		wantL     int  // expected top-level l (when present)
		wantConf  int  // expected top-level confidence
		wantNoL   bool // true when l is JSON null (manual thresholds)
	}{
		{
			name:      "hostile, level 3",
			raw:       `{"v":"6","prob":0.998,"l":3,"conf":97,"version":"vtest","fs":[{"id":0,"prob":0.998,"l":3,"conf":97}]}`,
			wantClass: 2,
			wantL:     3,
			wantConf:  97,
		},
		{
			name:      "hostile at the critical line",
			raw:       fmt.Sprintf(`{"v":"6","prob":0.91,"l":%[1]d,"conf":90,"version":"vtest","fs":[{"id":0,"prob":0.91,"l":%[1]d,"conf":90}]}`, CriticalLevel),
			wantClass: 2,
			wantL:     CriticalLevel,
			wantConf:  90,
		},
		{
			name:      "suspicious just past the critical line",
			raw:       fmt.Sprintf(`{"v":"6","prob":0.78,"l":%[1]d,"conf":89,"version":"vtest","fs":[{"id":0,"prob":0.78,"l":%[1]d,"conf":89}]}`, CriticalLevel+1),
			wantClass: 1,
			wantL:     CriticalLevel + 1,
			wantConf:  89,
		},
		{
			name:      "suspicious at the ceiling",
			raw:       fmt.Sprintf(`{"v":"6","prob":0.66,"l":%[1]d,"conf":85,"version":"vtest","fs":[{"id":0,"prob":0.66,"l":%[1]d,"conf":85}]}`, SuspiciousCeiling),
			wantClass: 1,
			wantL:     SuspiciousCeiling,
			wantConf:  85,
		},
		{
			name:      "benign past the ceiling",
			raw:       fmt.Sprintf(`{"v":"6","prob":0.5,"l":%[1]d,"conf":80,"version":"vtest","fs":[{"id":0,"prob":0.5,"l":%[1]d,"conf":80}]}`, SuspiciousCeiling+1),
			wantClass: 0,
			wantL:     SuspiciousCeiling + 1,
			wantConf:  80,
		},
		{
			name:      "benign sentinel, level -1",
			raw:       `{"v":"6","prob":0.04,"l":-1,"conf":0,"version":"vtest","fs":[{"id":0,"prob":0.04,"l":-1,"conf":0}]}`,
			wantClass: 0,
			wantL:     -1,
			wantConf:  0,
		},
		{
			name:      "hostile under manual thresholds, null level",
			raw:       `{"v":"6","prob":0.99,"l":null,"version":"vtest","fs":[{"id":0,"prob":0.99,"l":null}]}`,
			wantClass: 2,
			wantConf:  100,
			wantNoL:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ml litmusMlResponse
			if err := json.Unmarshal([]byte(tc.raw), &ml); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if ml.V != "6" {
				t.Errorf("V = %q, want 6", ml.V)
			}
			if got := ml.verdictClass(); got != tc.wantClass {
				t.Errorf("verdictClass() = %d (%s), want %d (%s)",
					got, classificationName(got), tc.wantClass, classificationName(tc.wantClass))
			}
			if ml.Confidence != tc.wantConf {
				t.Errorf("Confidence = %d, want %d", ml.Confidence, tc.wantConf)
			}
			switch {
			case tc.wantNoL && ml.L != nil:
				t.Errorf("L = %v, want nil", *ml.L)
			case !tc.wantNoL && ml.L == nil:
				t.Errorf("L = nil, want %d", tc.wantL)
			case !tc.wantNoL && ml.L != nil && *ml.L != tc.wantL:
				t.Errorf("L = %d, want %d", *ml.L, tc.wantL)
			}
			// The per-file marker must derive to the same class as the parent
			// (the merge in renderResult relies on this).
			if len(ml.Files) > 0 {
				if got := classFromLevel(ml.Files[0].L); got != tc.wantClass {
					t.Errorf("classFromLevel(fs[0].l) = %d, want %d", got, tc.wantClass)
				}
				if ml.Files[0].Conf != nil && *ml.Files[0].Conf != tc.wantConf {
					t.Errorf("fs[0].conf = %d, want %d", *ml.Files[0].Conf, tc.wantConf)
				}
			}
		})
	}
}

// TestLitmusMlResponseV7Verdict covers the current litmus wire names:
// lvl/files at the envelope and per-file levels.
func TestLitmusMlResponseV7Verdict(t *testing.T) {
	raw := `{"v":"7","prob":0.998,"lvl":3,"conf":97,"version":"vtest","files":[{"id":0,"prob":0.998,"lvl":3,"conf":97}]}`
	var ml litmusMlResponse
	if err := json.Unmarshal([]byte(raw), &ml); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ml.V != "7" {
		t.Errorf("V = %q, want 7", ml.V)
	}
	if got := ml.verdictClass(); got != 2 {
		t.Errorf("verdictClass() = %d (%s), want hostile", got, classificationName(got))
	}
	if ml.L == nil || *ml.L != 3 {
		t.Fatalf("L = %v, want 3", ml.L)
	}
	if ml.Confidence != 97 {
		t.Errorf("Confidence = %d, want 97", ml.Confidence)
	}
	if len(ml.Files) != 1 {
		t.Fatalf("len(Files) = %d, want 1", len(ml.Files))
	}
	if ml.Files[0].L == nil || *ml.Files[0].L != 3 {
		t.Errorf("Files[0].L = %v, want 3", ml.Files[0].L)
	}
	if ml.Files[0].Conf == nil || *ml.Files[0].Conf != 97 {
		t.Errorf("Files[0].Conf = %v, want 97", ml.Files[0].Conf)
	}
}

// TestLitmusEnvelopeLLM confirms the optional `llm` interpretation object is
// parsed from its top-level envelope slot (a sibling of `ml`/`raw`, not nested
// inside `ml`) when present, and is absent otherwise (the common case).
func TestLitmusEnvelopeLLM(t *testing.T) {
	raw := `{"ml":{"v":"7","prob":0.37,"lvl":-1,"conf":0,"files":[{"id":0,"prob":0.37,"lvl":-1}]},` +
		`"llm":{"grade":"benign","outcome":"benign","conf":0.5623,"review":false,` +
		`"interpretation":"Legitimate Harbor database container image","model":"test-model"},` +
		`"raw":{"files":[]}}`
	var env litmusFullResponse
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.LLM) == 0 {
		t.Fatal("LLM should be parsed from the top-level llm object")
	}
	var llm llmInterpretation
	if err := json.Unmarshal(env.LLM, &llm); err != nil {
		t.Fatalf("unmarshal llm: %v", err)
	}
	if llm.Interpretation != "Legitimate Harbor database container image" {
		t.Errorf("Interpretation = %q", llm.Interpretation)
	}
	if llm.Grade != "benign" || llm.Outcome != "benign" {
		t.Errorf("grade/outcome = %q/%q, want benign/benign", llm.Grade, llm.Outcome)
	}
	if llm.Conf < 0.56 || llm.Conf > 0.57 {
		t.Errorf("conf = %v, want ~0.5623", llm.Conf)
	}

	var bare litmusFullResponse
	if err := json.Unmarshal([]byte(`{"ml":{"v":"7","prob":0.1,"lvl":-1}}`), &bare); err != nil {
		t.Fatalf("unmarshal bare: %v", err)
	}
	if len(bare.LLM) != 0 {
		t.Errorf("LLM should be empty when no llm object is present, got %s", bare.LLM)
	}
}

// TestClassFromLevel exercises the consumer-side level policy directly,
// including the band boundaries. A nil l models v=6's manual-threshold case.
func TestClassFromLevel(t *testing.T) {
	cases := []struct {
		name string
		l    int
		nilL bool
		want int
	}{
		{name: "nil (manual thresholds) is hostile", nilL: true, want: 2},
		{name: "benign sentinel", l: -1, want: 0},
		{name: "level 0 is hostile", l: 0, want: 2},
		{name: "critical line is hostile", l: CriticalLevel, want: 2},
		{name: "just past the critical line is suspicious", l: CriticalLevel + 1, want: 1},
		{name: "suspicious ceiling is still suspicious", l: SuspiciousCeiling, want: 1},
		{name: "just past the ceiling is benign", l: SuspiciousCeiling + 1, want: 0},
		{name: "far past the ceiling is benign", l: SuspiciousCeiling * 2, want: 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var lp *int
			if !c.nilL {
				v := c.l
				lp = &v
			}
			if got := classFromLevel(lp); got != c.want {
				t.Errorf("classFromLevel = %d, want %d", got, c.want)
			}
		})
	}
}

// TestVerdictClassBackCompat confirms v=4/v=5 envelopes still read their
// verdict from `class`, since most of the corpus stays on the old shape
// during the migration window.
func TestVerdictClassBackCompat(t *testing.T) {
	for _, raw := range []string{
		`{"v":"4","class":2,"prob":0.998,"thresholds":[0.65,0.887]}`,
		`{"v":"5","class":2,"prob":0.998,"threshold":0.95,"level":3}`,
	} {
		var ml litmusMlResponse
		if err := json.Unmarshal([]byte(raw), &ml); err != nil {
			t.Fatalf("unmarshal %q: %v", raw, err)
		}
		if got := ml.verdictClass(); got != 2 {
			t.Errorf("verdictClass() for %s = %d, want 2", raw, got)
		}
	}
}
