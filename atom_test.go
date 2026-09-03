package main

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

func TestBuildAtomFeed(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	rows := []feedRow{
		{
			SHA256:         testSHAHero,
			Filename:       "ext.crx",
			Package:        "kpeiokhfmoigdhgmiippgkbnilhmmoim",
			Version:        "5.2.1",
			RegistryTitle:  "Volume Max",
			Users:          "412,033",
			Classification: "hostile",
			Ecosystem:      "chrome",
			Why:            "posts every visited URL to a hardcoded endpoint",
			AnalyzedAt:     now.Add(-2 * time.Hour),
		},
		// No LLM rationale: the summary degrades to the trait chips.
		{
			SHA256:         testSHABare,
			Filename:       testSHABare + ".elf",
			Classification: "hostile",
			Ecosystem:      "linux",
			TopTraits: []feedTrait{
				{ID: "persist.systemd-unit", Full: "objectives/persist/systemd-unit", Crit: "hostile"},
			},
			AnalyzedAt: now.Add(-3 * time.Hour),
		},
		// Neither rationale nor traits: the classification is the summary.
		{
			SHA256:         testSHARow,
			Filename:       "bare.bin",
			Classification: "hostile",
			AnalyzedAt:     now.Add(-4 * time.Hour),
		},
	}
	out, err := buildAtomFeed(rows, "https://lab.atomdrift.org", now)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"Volume Max 5.2.1 (hostile · chrome)",
		"urn:sha256:" + testSHAHero,
		"https://lab.atomdrift.org/file/" + testSHAHero,
		"posts every visited URL to a hardcoded endpoint",
		"Marketplace reach: 412,033 installs.",
		"Traits: persist.systemd-unit.",
		"Classified hostile by litmus analysis.",
		rows[0].AnalyzedAt.Format(time.RFC3339), // feed updated = newest row
	} {
		if !strings.Contains(got, want) {
			t.Errorf("atom feed missing %q", want)
		}
	}
	// Well-formed: the document round-trips through the same structs.
	var doc atomDoc
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(doc.Entries))
	}

	// The entry cap bounds the document, not the snapshot.
	many := make([]feedRow, atomFeedLimit+10)
	for i := range many {
		many[i] = rows[0]
	}
	out, err = buildAtomFeed(many, "https://lab.atomdrift.org", now)
	if err != nil {
		t.Fatal(err)
	}
	doc = atomDoc{}
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Entries) != atomFeedLimit {
		t.Errorf("entries = %d, want cap %d", len(doc.Entries), atomFeedLimit)
	}
}

func TestParseTopTraits(t *testing.T) {
	if got := parseTopTraits(""); got != nil {
		t.Errorf("empty column: got %v, want nil", got)
	}
	if got := parseTopTraits("{nope"); got != nil {
		t.Errorf("malformed column: got %v, want nil", got)
	}
	got := parseTopTraits(`[{"id":"objectives/exfil/dns-tunnel","crit":5},{"id":"objectives/exfil/dns-tunnel::variant-b","crit":4},{"id":"micro-behaviors/net/beacon","crit":4}]`)
	want := []feedTrait{
		{ID: "exfil/dns-tunnel", Full: "objectives/exfil/dns-tunnel", Crit: "hostile"},
		{ID: "net/beacon", Full: "micro-behaviors/net/beacon", Crit: "suspicious"},
	}
	if len(got) != len(want) {
		t.Fatalf("chips = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chip %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestTraitChipID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"objectives/exfil/dns-tunnel", "exfil/dns-tunnel"},
		{"micro-behaviors/net/beacon/hardcoded-c2", "beacon/hardcoded-c2"},
		{"exfil/dns", "exfil/dns"},
		{"standalone", "standalone"},
		{"objectives/cred/brute-force/iot-creds::mirai-credential-busybox-stager", "brute-force/iot-creds"},
		{"standalone::named", "standalone"},
	}
	for _, tc := range cases {
		if got := traitChipID(tc.in); got != tc.want {
			t.Errorf("traitChipID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestResultTemplateIdentity covers item-4 consistency: the detail hero wears
// the same identity grammar as the feed row that was clicked, plus the
// marketplace listing line, install count, and social-preview tags.
func TestResultTemplateIdentity(t *testing.T) {
	tmpl := resultTemplateForTest(t)
	data := singleFileData()
	data.Headline = "Volume Max 5.2.1"
	data.RegistryDesc = "Boost your volume up to 600%."
	data.Users = "412,033"
	data.MetaDesc = "posts every visited URL to a hardcoded endpoint"
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		`<title>Volume Max 5.2.1 - `,
		`property="og:title" content="Volume Max 5.2.1 — BENIGN"`,
		`property="og:description" content="posts every visited URL to a hardcoded endpoint"`,
		`>Volume Max 5.2.1</h1>`,
		"“Boost your volume up to 600%.”",
		">412,033 installs<",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("result page missing %q", want)
		}
	}
}
