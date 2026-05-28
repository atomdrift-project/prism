package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLitmusMlResponseV4 confirms the existing v=4 parse path still works
// (regression guard for the back-compat fallback that templates rely on).
func TestLitmusMlResponseV4(t *testing.T) {
	raw := []byte(`{"v":"4","class":2,"prob":0.998,"thresholds":[0.65,0.887],"version":"vtest","fs":[{"id":0,"class":2,"prob":0.998}]}`)
	var ml litmusMlResponse
	if err := json.Unmarshal(raw, &ml); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ml.V != "4" {
		t.Errorf("V = %q, want 4", ml.V)
	}
	if ml.suspiciousT() != 0.65 {
		t.Errorf("suspiciousT = %f, want 0.65", ml.suspiciousT())
	}
	if ml.hostileT() != 0.887 {
		t.Errorf("hostileT = %f, want 0.887", ml.hostileT())
	}
	if ml.Threshold != 0 {
		t.Errorf("Threshold = %f, want 0 (v=4 leaves it zero)", ml.Threshold)
	}
	if ml.Level != nil {
		t.Errorf("Level = %v, want nil (v=4 has no level)", ml.Level)
	}
}

// TestLitmusMlResponseV5 covers the new envelope shape end-to-end.
func TestLitmusMlResponseV5(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		class     int
		threshold float64
		wantLevel *int
	}{
		{
			name:      "hostile, level 3",
			raw:       `{"v":"5","class":2,"prob":0.998,"threshold":0.95,"level":3,"version":"vtest","fs":[{"id":0,"class":2,"prob":0.998,"threshold":0.95}]}`,
			class:     2,
			threshold: 0.95,
			wantLevel: intp(3), //nolint:modernize // new(int) doesn't accept a value
		},
		{
			name:      "suspicious, level 5",
			raw:       `{"v":"5","class":1,"prob":0.75,"threshold":0.70,"level":5,"version":"vtest","fs":[{"id":0,"class":1,"prob":0.75,"threshold":0.70}]}`,
			class:     1,
			threshold: 0.70,
			wantLevel: intp(5), //nolint:modernize // new(int) doesn't accept a value
		},
		{
			name:      "benign, null level (manual thresholds)",
			raw:       `{"v":"5","class":0,"prob":0.10,"threshold":0.65,"level":null,"version":"vtest","fs":[{"id":0,"class":0,"prob":0.10,"threshold":0.65}]}`,
			class:     0,
			threshold: 0.65,
			wantLevel: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ml litmusMlResponse
			if err := json.Unmarshal([]byte(tc.raw), &ml); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if ml.V != "5" {
				t.Errorf("V = %q, want 5", ml.V)
			}
			if ml.Classification != tc.class {
				t.Errorf("Classification = %d, want %d", ml.Classification, tc.class)
			}
			if ml.Threshold != tc.threshold {
				t.Errorf("Threshold = %f, want %f", ml.Threshold, tc.threshold)
			}
			switch {
			case tc.wantLevel == nil && ml.Level != nil:
				t.Errorf("Level = %v, want nil", *ml.Level)
			case tc.wantLevel != nil && ml.Level == nil:
				t.Errorf("Level = nil, want %v", *tc.wantLevel)
			case tc.wantLevel != nil && ml.Level != nil && *ml.Level != *tc.wantLevel:
				t.Errorf("Level = %d, want %d", *ml.Level, *tc.wantLevel)
			}
			// Per-file threshold round-trips too.
			if len(ml.Files) > 0 && ml.Files[0].Threshold != tc.threshold {
				t.Errorf("Files[0].Threshold = %f, want %f", ml.Files[0].Threshold, tc.threshold)
			}
			// v5BandEdges still derives a sensible (suspT, hostT) pair for the
			// legacy back-compat readers that fall back to the two-edge model.
			suspT, hostT := ml.v5BandEdges()
			if suspT >= hostT {
				t.Errorf("v5BandEdges returned suspT (%f) >= hostT (%f)", suspT, hostT)
			}
		})
	}
}

// TestClassifyByThresholds verifies the v=4 band classifier used by
// bandGradient.
func TestClassifyByThresholds(t *testing.T) {
	cases := []struct {
		p, suspT, hostT float64
		want            int
	}{
		{0.10, 0.65, 0.90, 0}, // benign
		{0.65, 0.65, 0.90, 1}, // exactly at suspicious cutoff
		{0.85, 0.65, 0.90, 1}, // suspicious
		{0.90, 0.65, 0.90, 2}, // exactly at hostile cutoff
		{0.99, 0.65, 0.90, 2}, // hostile
	}
	for _, c := range cases {
		got := classifyByThresholds(c.p, c.suspT, c.hostT)
		if got != c.want {
			t.Errorf("classifyByThresholds(%f, %f, %f) = %d, want %d", c.p, c.suspT, c.hostT, got, c.want)
		}
	}
}

// TestBandProgressV5 covers the within-band progress for the v=5 single-
// threshold rendering path.
func TestBandProgressV5(t *testing.T) {
	cases := []struct {
		name      string
		p         float64
		threshold float64
		class     int
		wantMin   float64
		wantMax   float64
	}{
		{"hostile at threshold", 0.95, 0.95, 2, 0.0, 0.001},
		{"hostile midway to 1", 0.975, 0.95, 2, 0.49, 0.51},
		{"hostile at 1", 1.0, 0.95, 2, 0.999, 1.0},
		{"suspicious at threshold", 0.65, 0.65, 1, 0.0, 0.001},
		{"benign at zero", 0.0, 0.65, 0, 0.0, 0.001},
		{"benign at threshold", 0.65, 0.65, 0, 0.999, 1.0},
		{"benign midway", 0.325, 0.65, 0, 0.49, 0.51},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := bandProgressV5(c.p, c.threshold, c.class)
			if got < c.wantMin || got > c.wantMax {
				t.Errorf("bandProgressV5(%f, %f, %d) = %f, want in [%f, %f]",
					c.p, c.threshold, c.class, got, c.wantMin, c.wantMax)
			}
		})
	}
}

// TestRenderBandGradientShape just confirms the helper emits a well-formed
// CSS string for each band (sanity guard; exact colors are visual).
func TestRenderBandGradientShape(t *testing.T) {
	for _, class := range []int{0, 1, 2} {
		css := string(renderBandGradient(0.5, 0.5, class))
		if !strings.HasPrefix(css, "linear-gradient(90deg,") {
			t.Errorf("class=%d: CSS missing linear-gradient prefix: %q", class, css)
		}
		if !strings.Contains(css, "rgb(") {
			t.Errorf("class=%d: CSS missing rgb() stops: %q", class, css)
		}
	}
}

// intp returns a pointer to the int literal. modernize wants this expressed
// as `new(...)`, but new can't take a value — keeping the helper as the
// readable Go idiom.
//
//nolint:modernize // new() doesn't accept a value; helper is the clearest form
func intp(v int) *int { return &v }
