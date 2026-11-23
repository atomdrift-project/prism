package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/atomdrift-project/hopper"
)

// GET /{sha256} is a file's address. A browser gets the detail page that
// /file/{sha256} serves; anything else gets the record beamline's
// /v1/lookup?sha256= answers with, in the same shape, so a script can ask
// `curl https://sha256.is/<digest>` and branch on one field.

// lookupTimeout bounds the hopper read behind a JSON answer. The record is an
// indexed read; a caller waiting longer than this is better told
// "unavailable" and left to retry.
const lookupTimeout = 5 * time.Second

// defaultFalsePositiveBudget is beamline's default false_positive_budget,
// which is prism's hostile cutoff.
const defaultFalsePositiveBudget = CriticalLevel

// maxFalsePositiveBudget is the loosest budget a caller may ask for, as
// beamline bounds it.
const maxFalsePositiveBudget = 3000

// lookupAnswer is one artifact as beamline's /v1/lookup reports it. Fields
// with nothing to say are omitted; findings is always present.
type lookupAnswer struct {
	FiresAt       *int            `json:"fires_at,omitempty"`
	Status        string          `json:"status"`
	PURL          string          `json:"purl,omitempty"`
	SHA256        string          `json:"sha256,omitempty"`
	Severity      string          `json:"severity"`
	Reason        string          `json:"reason,omitempty"`
	Cause         string          `json:"cause,omitempty"`
	EngineVersion string          `json:"engine_version,omitempty"`
	AnalyzedAt    string          `json:"analyzed_at,omitempty"`
	Findings      []lookupFinding `json:"findings"`
}

type lookupFinding struct {
	ID   string `json:"id"`
	Desc string `json:"desc,omitempty"`
	Crit int    `json:"crit"`
}

// handleSHA serves GET /{sha256}; sha is validated lowercase hex.
func handleSHA(w http.ResponseWriter, r *http.Request, sha string) {
	w.Header().Add("Vary", "Accept")
	if acceptsHTML(r) {
		r.SetPathValue("sha256", sha)
		handleFile(w, r)
		return
	}
	serveLookup(w, r, sha)
}

// acceptsHTML reports whether the client asked for HTML. Every browser's
// navigation sends text/html in Accept; curl, wget and HTTP libraries send
// */* or nothing.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// serveLookup answers with sha's record as beamline's /v1/lookup would. As
// there, an answer is always a 200: "unanalyzed" and "unavailable" are
// statuses, not errors. Only a malformed request is refused.
func serveLookup(w http.ResponseWriter, r *http.Request, sha string) {
	start := time.Now()
	raw := r.URL.Query().Get("false_positive_budget")
	budget, ok := parseBudget(raw)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{
			"code":    "invalid_false_positive_budget",
			"message": fmt.Sprintf("false_positive_budget must be a whole number from 0 to %d, not %q.", maxFalsePositiveBudget, raw),
		}})
		return
	}
	rec, err := lookupRecord(r.Context(), sha)
	a := answerFor(sha, rec, err, budget)
	logger.Info("sha lookup",
		"sha256", sha,
		"status", a.Status,
		"severity", a.Severity,
		"budget", budget,
		"client_ip", clientIP(r),
		"user_agent", r.UserAgent(),
		"duration_ms", time.Since(start).Milliseconds(),
		"error", err,
	)
	if a.Status != "analyzed" {
		// A miss or an outage now is not one a minute from now.
		w.Header().Set("Cache-Control", "no-store")
	}
	writeJSON(w, http.StatusOK, a)
}

// parseBudget reads false_positive_budget: absent is the default, anything
// but a whole number from 0 to maxFalsePositiveBudget is refused rather than
// quietly replaced, as beamline refuses it.
func parseBudget(raw string) (int, bool) {
	if raw == "" {
		return defaultFalsePositiveBudget, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > maxFalsePositiveBudget {
		return 0, false
	}
	return n, true
}

// lookupRecord reads the record hopper's /v1/lookup serves for sha, gated by
// the shared hopper-db breaker. hopper.ErrNotFound means nothing is known.
func lookupRecord(ctx context.Context, sha string) (*hopper.LookupRecord, error) {
	st := hopperStore.Load()
	if st == nil {
		return nil, errors.New("hopper db not connected")
	}
	if err := dbBreaker.allow(); err != nil {
		recordDep(ctx, "hopper-db", "sha-lookup", "rejected", time.Time{})
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	start := time.Now()
	rec, err := hopper.LookupStore(ctx, st, sha, "", "")
	if err != nil && !errors.Is(err, hopper.ErrNotFound) {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "sha-lookup", "error", start)
		return nil, err
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "sha-lookup", "ok", start)
	return rec, err
}

// answerFor turns hopper's record into beamline's answer, the way scan and
// beamline do between them: a record with no level, or bytes nothing has
// judged yet, is "unanalyzed"; severity is fires_at read at budget.
func answerFor(sha string, rec *hopper.LookupRecord, err error, budget int) lookupAnswer {
	a := lookupAnswer{Status: "unanalyzed", SHA256: sha, Severity: "unknown", Findings: []lookupFinding{}}
	switch {
	case errors.Is(err, hopper.ErrNotFound):
		return a
	case err != nil:
		a.Status, a.Cause = "unavailable", "unreachable"
		return a
	}
	a.PURL = derefString(rec.PURL)
	if rec.State == hopper.StatePending || rec.FiresAt == nil {
		return a
	}
	if s := derefString(rec.SHA256); s != "" {
		a.SHA256 = s
	}
	a.Status = "analyzed"
	a.FiresAt = rec.FiresAt
	a.Severity = severityAt(*rec.FiresAt, budget)
	a.Reason = derefString(rec.Reason)
	a.EngineVersion = derefString(rec.EngineVersion)
	a.AnalyzedAt = derefString(rec.AnalyzedAt)
	for _, f := range rec.Findings {
		a.Findings = append(a.Findings, lookupFinding{ID: f.ID, Desc: f.Desc, Crit: f.Crit})
	}
	return a
}

// severityAt reads a measured level at a caller's budget: -1 never fires; at
// or under the budget is hostile; past it but within the budget's suspicious
// ceiling (scan's, which scales with the budget) is suspicious; looser still
// is benign.
func severityAt(level, budget int) string {
	switch {
	case level < 0:
		return "benign"
	case level <= budget:
		return "hostile"
	case level <= suspiciousCeiling(budget):
		return "suspicious"
	default:
		return "benign"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Debug("json write failed", "error", err)
	}
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
