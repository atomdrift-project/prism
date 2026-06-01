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
		wantNoL   bool // true when l is JSON null (manual thresholds)
	}{
		{
			name:      "hostile, level 3",
			raw:       `{"v":"6","prob":0.998,"l":3,"version":"vtest","fs":[{"id":0,"prob":0.998,"l":3}]}`,
			wantClass: 2,
			wantL:     3,
		},
		{
			name:      "hostile at the band edge, level 50",
			raw:       `{"v":"6","prob":0.91,"l":50,"version":"vtest","fs":[{"id":0,"prob":0.91,"l":50}]}`,
			wantClass: 2,
			wantL:     50,
		},
		{
			name:      "suspicious just past the edge, level 51",
			raw:       `{"v":"6","prob":0.78,"l":51,"version":"vtest","fs":[{"id":0,"prob":0.78,"l":51}]}`,
			wantClass: 1,
			wantL:     51,
		},
		{
			name:      "suspicious, level 100 (range ceiling)",
			raw:       `{"v":"6","prob":0.66,"l":100,"version":"vtest","fs":[{"id":0,"prob":0.66,"l":100}]}`,
			wantClass: 1,
			wantL:     100,
		},
		{
			name:      "benign sentinel, level -1",
			raw:       `{"v":"6","prob":0.04,"l":-1,"version":"vtest","fs":[{"id":0,"prob":0.04,"l":-1}]}`,
			wantClass: 0,
			wantL:     -1,
		},
		{
			name:      "hostile under manual thresholds, null level",
			raw:       `{"v":"6","prob":0.99,"l":null,"version":"vtest","fs":[{"id":0,"prob":0.99,"l":null}]}`,
			wantClass: 2,
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
			}
		})
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
