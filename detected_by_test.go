package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	"github.com/atomdrift-project/hopper"
)

// newTestHopper returns an empty migrated ledger wired in as the one detectedBy
// reads, and silences the package logger so a lookup warning does not nil-panic.
func newTestHopper(t *testing.T, ctx context.Context) *hopper.DB {
	t.Helper()
	logger = slog.New(slog.DiscardHandler)
	db, err := hopper.Open(ctx, filepath.Join(t.TempDir(), "h.db"), hopper.AppName("prism"))
	if err != nil {
		t.Fatalf("open hopper: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate hopper: %v", err)
	}
	hopperDB.Store(db)
	t.Cleanup(func() { hopperDB.Store(nil) })
	return db
}

// A package-level claim naming other releases must not be shown against this
// one.
//
// Reported against two ordinary releases of packages that were compromised
// much later: is 0.1.2 and @tanstack/router-devtools-core 1.162.6. Both pages
// rendered "Also flagged by osv" from MAL-2025-6020 (is 3.3.1, 5.0.0) and
// MAL-2026-3475 (1.167.6, 1.167.9) — advisories that name neither release —
// while the page's own verdict was benign and its label clean.
//
// The ledger keys package claims on the version-less purl_base, so
// SightingsFor answering with them is correct; narrowing to the release is
// this caller's job, and was the step that was missing.
func TestDetectedByNarrowsToTheReleaseCited(t *testing.T) {
	ctx := context.Background()
	db := newTestHopper(t, ctx)

	const purl = "pkg:npm/is"
	if _, err := db.AddSightings(ctx, []hopper.Sighting{
		{
			Source:   "osv",
			Subject:  purl,
			Affected: "3.3.1, 5.0.0",
			Claim:    hopper.ClaimMalicious,
			URL:      "https://osv.dev/vulnerability/MAL-2025-6020",
			Note:     "MAL-2025-6020: Malicious code in is (npm)",
		},
	}); err != nil {
		t.Fatalf("add sightings: %v", err)
	}

	sha := "9f07e3bb52685587a6a94e721c5f44830a4fa5ccd1b064f796e13f33a18e00fe"
	if named, more := detectedBy(ctx, sha, purl, "0.1.2"); len(named) != 0 || more != "" {
		t.Errorf("0.1.2 is not named by the advisory, got named=%v more=%q", named, more)
	}
	named, _ := detectedBy(ctx, sha, purl, "3.3.1")
	if !slices.ContainsFunc(named, func(c Citation) bool { return c.Source == "osv" }) {
		t.Errorf("3.3.1 IS named by the advisory; the citation was lost: %v", named)
	}
}

// A vulnerability is a defect in legitimate software. Listing a CVE under
// "also flagged by" states the opposite of what the advisory says, and an
// unscoped one would do it for every release.
func TestDetectedBySkipsVulnerabilities(t *testing.T) {
	ctx := context.Background()
	db := newTestHopper(t, ctx)

	const purl = "pkg:npm/legit"
	if _, err := db.AddSightings(ctx, []hopper.Sighting{
		{
			Source:   "osv",
			Subject:  purl,
			Affected: hopper.AllVersions,
			Claim:    hopper.ClaimVulnerable,
			Note:     "CVE-2024-0001",
		},
	}); err != nil {
		t.Fatalf("add sightings: %v", err)
	}
	if named, more := detectedBy(ctx, "", purl, "1.0.0"); len(named) != 0 || more != "" {
		t.Errorf("a CVE is not a malware citation, got named=%v more=%q", named, more)
	}
}

// An unnarrowable scope still speaks for the package. Hiding those would lose
// real citations, which is the opposite failure to the one above.
func TestDetectedByKeepsUnnarrowableClaims(t *testing.T) {
	ctx := context.Background()
	db := newTestHopper(t, ctx)

	const purl = "pkg:npm/allbad"
	for _, affected := range []string{"", hopper.AllVersions, ">= 0", "<2.0.0"} {
		if _, err := db.AddSightings(ctx, []hopper.Sighting{
			{Source: "osv", Subject: purl, Affected: affected, Claim: hopper.ClaimMalicious},
		}); err != nil {
			t.Fatalf("add sightings: %v", err)
		}
		named, _ := detectedBy(ctx, "", purl, "9.9.9")
		if !slices.ContainsFunc(named, func(c Citation) bool { return c.Source == "osv" }) {
			t.Errorf("affected %q speaks for the whole package; citation lost", affected)
		}
	}
}
