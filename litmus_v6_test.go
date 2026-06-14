package main

import (
	"encoding/json"
	"testing"
)

// TestLitmusMlResponseV6Verdict covers the collapsed v=6 envelope through the
// consumer-side verdict path: `class` and `threshold` are gone from the wire,
// replaced by the single `l` verdict-and-level marker both at the top level
// and inside fs[]. Unlike TestLitmusMlResponseV6 in litmus_v5_test.go (which
// exercises the envelopeClass 0/2 mapping), this asserts the classFromLevel
// policy, including the suspicious band at level >= 51.
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
			name:      "hostile at the band edge, level 50",
			raw:       `{"v":"6","prob":0.91,"l":50,"conf":90,"version":"vtest","fs":[{"id":0,"prob":0.91,"l":50,"conf":90}]}`,
			wantClass: 2,
			wantL:     50,
			wantConf:  90,
		},
		{
			name:      "suspicious just past the edge, level 51",
			raw:       `{"v":"6","prob":0.78,"l":51,"conf":89,"version":"vtest","fs":[{"id":0,"prob":0.78,"l":51,"conf":89}]}`,
			wantClass: 1,
			wantL:     51,
			wantConf:  89,
		},
		{
			name:      "suspicious, level 100 (range ceiling)",
			raw:       `{"v":"6","prob":0.66,"l":100,"conf":85,"version":"vtest","fs":[{"id":0,"prob":0.66,"l":100,"conf":85}]}`,
			wantClass: 1,
			wantL:     100,
			wantConf:  85,
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

// TestLitmusMlResponseLLM confirms the optional `llm` interpretation object is
// parsed when present and left nil otherwise (the common case).
func TestLitmusMlResponseLLM(t *testing.T) {
	raw := `{"v":"7","prob":0.37,"lvl":-1,"conf":0,` +
		`"llm":{"grade":"benign","outcome":"benign","conf":0.5623,"review":false,` +
		`"interpretation":"Legitimate Harbor database container image","model":"test-model"},` +
		`"files":[{"id":0,"prob":0.37,"lvl":-1}]}`
	var ml litmusMlResponse
	if err := json.Unmarshal([]byte(raw), &ml); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ml.LLM == nil {
		t.Fatal("LLM should be parsed from the llm object")
	}
	if ml.LLM.Interpretation != "Legitimate Harbor database container image" {
		t.Errorf("Interpretation = %q", ml.LLM.Interpretation)
	}
	if ml.LLM.Grade != "benign" || ml.LLM.Outcome != "benign" {
		t.Errorf("grade/outcome = %q/%q, want benign/benign", ml.LLM.Grade, ml.LLM.Outcome)
	}
	if ml.LLM.Review {
		t.Error("review should be false")
	}
	if ml.LLM.Conf < 0.56 || ml.LLM.Conf > 0.57 {
		t.Errorf("conf = %v, want ~0.5623", ml.LLM.Conf)
	}

	var bare litmusMlResponse
	if err := json.Unmarshal([]byte(`{"v":"7","prob":0.1,"lvl":-1}`), &bare); err != nil {
		t.Fatalf("unmarshal bare: %v", err)
	}
	if bare.LLM != nil {
		t.Errorf("LLM should be nil when no llm object is present, got %+v", bare.LLM)
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
		{name: "level 50 is hostile", l: 50, want: 2},
		{name: "level 51 is suspicious", l: 51, want: 1},
		{name: "level 100 (range ceiling) is suspicious", l: 100, want: 1},
		{name: "out-of-range level stays suspicious", l: 500, want: 1},
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
