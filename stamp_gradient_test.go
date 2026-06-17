package main

import (
	"fmt"
	"strings"
	"testing"
)

// TestLevelColorAnchors pins the violet→red→orange→yellow→green spectrum to the
// level scale. These are the exact anchors a stamp is colored from, so a drift
// here is a visible verdict-stamp change.
func TestLevelColorAnchors(t *testing.T) {
	cases := []struct {
		level               int
		wantR, wantG, wantB int
	}{
		{0, 150, 50, 225},    // violet (strictest)
		{1, 235, 55, 55},     // red
		{50, 250, 140, 35},   // orange (default operating level)
		{150, 240, 205, 60},  // yellow
		{500, 150, 200, 80},  // greenish
		{1000, 85, 195, 115}, // green (loosest)
		{5000, 85, 195, 115}, // clamps to the loosest anchor
	}
	for _, c := range cases {
		got := levelColor(c.level)
		if int(got.r) != c.wantR || int(got.g) != c.wantG || int(got.b) != c.wantB {
			t.Errorf("levelColor(%d) = rgb(%d,%d,%d), want rgb(%d,%d,%d)",
				c.level, int(got.r), int(got.g), int(got.b), c.wantR, c.wantG, c.wantB)
		}
	}
}

// TestLevelGradientVerdicts guards the reported inconsistency: a hostile file at
// L50 must read as a warm (orange) stamp, never the benign green band, while the
// benign sentinel stays a solid green.
func TestLevelGradientVerdicts(t *testing.T) {
	// Benign sentinel: solid green (both stops identical, green dominant).
	benign := string(levelGradient(new(-1)))
	left, right := gradientStops(t, benign)
	if left != right {
		t.Errorf("benign gradient should be solid, got two stops: %q", benign)
	}
	if !(left.g > left.r && left.g > left.b) {
		t.Errorf("benign stamp should be green-dominant, got %v", left)
	}

	// Hostile at L50: warm/orange — red channel high, green mid, blue low. The
	// old probability-vs-threshold path rendered this green; that was the bug.
	hostile := levelGradient(new(50))
	l, _ := gradientStops(t, string(hostile))
	if !(l.r > 200 && l.b < 90 && l.r > l.g) {
		t.Errorf("L50 hostile stamp should be warm/orange, got %v (%q)", l, hostile)
	}

	// Manual-threshold hostile (nil level): red, not benign green.
	manual, _ := gradientStops(t, string(levelGradient(nil)))
	if !(manual.r > manual.g && manual.r > manual.b) {
		t.Errorf("nil-level hostile stamp should be red-dominant, got %v", manual)
	}
}

// TestStampGradientVersionDispatch verifies v6/v7 color by level while older
// envelopes keep the threshold-based band, so cached v4/v5 results are unchanged.
func TestStampGradientVersionDispatch(t *testing.T) {
	// v6 ignores prob/threshold and delegates to the level spectrum.
	if got := stampGradient("6", new(50), 0.99, 0, 0.65, 0.887, 2); got != levelGradient(new(50)) {
		t.Errorf("v6 stampGradient should equal levelGradient(50), got %q", got)
	}
	if got := stampGradient("7", new(50), 0.99, 0, 0.65, 0.887, 2); got != levelGradient(new(50)) {
		t.Errorf("v7 stampGradient should equal levelGradient(50), got %q", got)
	}
	// v5 (threshold > 0) and v4 (threshold 0) still produce a band gradient and
	// must not equal the level path for the same inputs.
	v5 := stampGradient("5", nil, 0.99, 0.8, 0.65, 0.887, 2)
	v4 := stampGradient("4", nil, 0.99, 0, 0.65, 0.887, 2)
	for name, got := range map[string]string{"v5": string(v5), "v4": string(v4)} {
		if !strings.HasPrefix(got, "linear-gradient(90deg,") {
			t.Errorf("%s gradient malformed: %q", name, got)
		}
		if got == string(levelGradient(nil)) {
			t.Errorf("%s should use the band path, not the level path", name)
		}
	}
}

// TestLevelConfidence pins the level→confidence percentage shown on the litmus
// badge. This mirrors litmus::scan::level_confidence for cached envelopes that
// predate ml.conf.
func TestLevelConfidence(t *testing.T) {
	cases := []struct {
		level *int
		want  int
	}{
		{nil, 100},    // manual-threshold hostile
		{new(-1), 0},  // benign sentinel
		{new(0), 100}, // strictest cutoff
		{new(1), 99},
		{new(2), 98},
		{new(5), 95},
		{new(50), 90}, // default operating level
		{new(100), 85},
		{new(500), 78},
		{new(1000), 75},
		{new(5000), 54},
		{new(25000), 29},
		{new(25001), 28},
		{new(25002), 27},
		{new(30000), 26},
		{new(50000), 17},
		{new(50001), 16},
		{new(50002), 15},
	}
	for _, c := range cases {
		if got := levelConfidence(c.level); got != c.want {
			t.Errorf("levelConfidence(%v) = %d, want %d", c.level, got, c.want)
		}
	}
}

// gradientStops parses "linear-gradient(90deg, rgb(a,b,c), rgb(d,e,f))" into its
// two color stops.
func gradientStops(t *testing.T, css string) (first, second bandRGB) {
	t.Helper()
	rgbs := make([]bandRGB, 0, 2)
	for _, part := range strings.Split(css, "rgb(")[1:] {
		body, _, ok := strings.Cut(part, ")")
		if !ok {
			t.Fatalf("malformed gradient: %q", css)
		}
		var r, g, b int
		if _, err := fmt.Sscanf(body, "%d,%d,%d", &r, &g, &b); err != nil {
			t.Fatalf("parse rgb %q: %v", body, err)
		}
		rgbs = append(rgbs, bandRGB{float64(r), float64(g), float64(b)})
	}
	if len(rgbs) != 2 {
		t.Fatalf("expected 2 stops, got %d in %q", len(rgbs), css)
	}
	return rgbs[0], rgbs[1]
}
