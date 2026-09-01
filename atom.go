package main

// The Fallout Atom feed: the hostile view as a subscription surface
// (/feed.atom). Served from the same cached hostile snapshot the frontpage
// uses, so a feed reader polling every few minutes costs one warm cache read
// and zero extra hopper work.

import (
	"encoding/xml"
	"net/http"
	"strings"
	"time"
)

// atomFeedLimit caps entries per fetch; feed readers keep their own history,
// so the subscription only needs the recent tail, not the whole snapshot.
const atomFeedLimit = 50

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
}

type atomAuthor struct {
	Name string `xml:"name"`
}

type atomEntry struct {
	Title   string   `xml:"title"`
	ID      string   `xml:"id"`
	Updated string   `xml:"updated"`
	Link    atomLink `xml:"link"`
	Summary string   `xml:"summary"`
}

type atomDoc struct {
	XMLName xml.Name    `xml:"feed"`
	Xmlns   string      `xml:"xmlns,attr"`
	Title   string      `xml:"title"`
	ID      string      `xml:"id"`
	Updated string      `xml:"updated"`
	Author  atomAuthor  `xml:"author"`
	Links   []atomLink  `xml:"link"`
	Entries []atomEntry `xml:"entry"`
}

// buildAtomFeed renders the newest-first hostile rows as Atom 1.0. base is
// the request origin ("https://lab.atomdrift.org"); entry ids use the
// urn:sha256 form so they stay stable across hosts and reorderings.
func buildAtomFeed(rows []feedRow, base string, now time.Time) ([]byte, error) {
	if len(rows) > atomFeedLimit {
		rows = rows[:atomFeedLimit]
	}
	updated := now
	if len(rows) > 0 {
		updated = rows[0].AnalyzedAt
	}
	doc := atomDoc{
		Xmlns:   "http://www.w3.org/2005/Atom", //nolint:revive // the Atom namespace is an identifier, not a URL; https is a different namespace
		Title:   "Fallout — hostile catches · atomdrift lab",
		ID:      base + "/",
		Updated: updated.UTC().Format(time.RFC3339),
		Author:  atomAuthor{Name: "atomdrift lab"},
		Links: []atomLink{
			{Href: base + "/feed.atom", Rel: "self", Type: "application/atom+xml"},
			{Href: base + "/?criticality=hostile", Rel: "alternate", Type: "text/html"},
		},
	}
	for i := range rows {
		row := &rows[i]
		title := row.Headline() + " (" + row.Classification
		if row.Ecosystem != "" {
			title += " · " + row.Ecosystem
		}
		title += ")"
		summary := row.Why
		if summary == "" && len(row.TopTraits) > 0 {
			ids := make([]string, len(row.TopTraits))
			for i, trait := range row.TopTraits {
				ids[i] = trait.ID
			}
			summary = "Traits: " + strings.Join(ids, ", ") + "."
		}
		if summary == "" {
			summary = "Classified " + row.Classification + " by litmus analysis."
		}
		if row.Users != "" {
			summary += " Marketplace reach: " + row.Users + " installs."
		}
		summary += " sha256: " + row.SHA256
		doc.Entries = append(doc.Entries, atomEntry{
			Title:   title,
			ID:      "urn:sha256:" + row.SHA256,
			Updated: row.AnalyzedAt.UTC().Format(time.RFC3339),
			Link:    atomLink{Href: base + "/file/" + row.SHA256, Rel: "alternate", Type: "text/html"},
			Summary: summary,
		})
	}
	return xml.MarshalIndent(doc, "", "  ")
}

// requestBaseURL reconstructs the request origin for the feed's absolute
// links: the proxy's X-Forwarded-Proto when present, else the connection's
// own scheme.
func requestBaseURL(r *http.Request) string {
	scheme := "https"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		scheme = proto
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func handleAtomFeed(w http.ResponseWriter, r *http.Request) {
	if hopperDB.Load() == nil {
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}
	snapshot, _, err := loadFeedSnapshot(r.Context(), &feedQueryArgs{criticality: "hostile"}, logger, false)
	if err != nil {
		logger.Warn("atom feed: hostile snapshot unavailable", "error", err)
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}
	out, err := buildAtomFeed(feedRowsFromSnapshot(snapshot), requestBaseURL(r), time.Now())
	if err != nil {
		logger.Error("atom feed: marshal failed", "error", err)
		http.Error(w, "feed unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	body := append([]byte(xml.Header), out...)
	if _, err := w.Write(body); err != nil {
		logger.Debug("atom feed: write failed", "error", err)
	}
}
