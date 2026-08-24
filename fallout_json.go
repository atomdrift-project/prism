package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// falloutJSONRow is one uncollapsed hostile catch. The HTML page intentionally
// turns campaigns into waves and trims singles for readability; triage needs
// every exact hash/PURL pair, so this representation stays one-to-one with
// the rows in the cached hostile snapshot.
type falloutJSONRow struct {
	AnalyzedAt     time.Time          `json:"analyzed_at"`
	Classification string             `json:"classification"`
	LLMGrade       string             `json:"llm_grade,omitempty"`
	PURL           string             `json:"purl,omitempty"`
	Ecosystem      string             `json:"ecosystem,omitempty"`
	Filename       string             `json:"filename,omitempty"`
	Package        string             `json:"package,omitempty"`
	PURLBase       string             `json:"purl_base,omitempty"`
	Version        string             `json:"version,omitempty"`
	Why            string             `json:"why,omitempty"`
	SHA256         string             `json:"sha256"`
	FileType       string             `json:"file_type,omitempty"`
	Formula        string             `json:"formula,omitempty"`
	Traits         []falloutJSONTrait `json:"traits,omitempty"`
	Downloads      int64              `json:"downloads,omitempty"`
	Confidence     int                `json:"confidence,omitempty"`
	Corroborated   bool               `json:"corroborated"`
}

type falloutJSONTrait struct {
	ID   string `json:"id"`
	Full string `json:"full,omitempty"`
	Crit string `json:"criticality,omitempty"`
	Href string `json:"href,omitempty"`
}

func falloutJSONRows(rows []feedRow) []falloutJSONRow {
	out := make([]falloutJSONRow, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		item := falloutJSONRow{
			SHA256:         row.SHA256,
			PURL:           feedPURL(row.PURLBase, row.Version),
			PURLBase:       purlDisplayString(row.PURLBase),
			AnalyzedAt:     row.AnalyzedAt,
			Ecosystem:      row.Ecosystem,
			Filename:       row.Filename,
			Package:        row.Package,
			Version:        row.Version,
			Classification: row.Classification,
			Why:            row.Why,
			LLMGrade:       row.LLMGrade,
			Confidence:     row.Conf,
			Corroborated:   row.Corroborated,
			Downloads:      row.Downloads,
			Formula:        row.Formula,
			FileType:       row.FileType,
		}
		if len(row.TopTraits) > 0 {
			item.Traits = make([]falloutJSONTrait, 0, len(row.TopTraits))
			for _, trait := range row.TopTraits {
				item.Traits = append(item.Traits, falloutJSONTrait(trait))
			}
		}
		out = append(out, item)
	}
	return out
}

func feedPURL(base, version string) string {
	if base == "" || version == "" {
		return purlDisplayString(base)
	}
	return purlDisplayString(base) + "@" + version
}

func handleFalloutJSON(w http.ResponseWriter, r *http.Request) {
	verified, err := parseFalloutVerification(r.URL.Query().Get("verified"))
	if err != nil {
		writeFalloutJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if hopperDB.Load() == nil {
		writeFalloutJSONError(w, http.StatusServiceUnavailable, "fallout unavailable")
		return
	}

	// Keep this query identical to handleFallout. `verified` is applied after
	// the shared snapshot read, so it never creates a second cache entry.
	snapshot, _, err := loadFeedSnapshot(
		r.Context(), feedQueryArgs{criticality: "hostile"}, logger, isHardRefresh(r),
	)
	if err != nil {
		logger.Warn("fallout JSON: hostile snapshot unavailable", "error", err)
		writeFalloutJSONError(w, http.StatusServiceUnavailable, "fallout unavailable")
		return
	}

	rows := falloutRowsInWindow(feedRowsFromSnapshot(snapshot), time.Now(), verified)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(falloutJSONRows(rows)); err != nil {
		logger.Debug("fallout JSON: write failed", "error", err)
	}
}

func writeFalloutJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message}); err != nil {
		logger.Debug("fallout JSON: error write failed", "error", err)
	}
}
