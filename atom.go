package main

// The Atom feeds: the Malware list (/malware.atom) and the week's Fallout
// (/fallout.atom) as subscription surfaces. Each is served from the same cached
// snapshot its page renders from, so a feed reader polling every few minutes
// costs one warm cache read and zero extra hopper work.

import (
	"encoding/xml"
	"net/http"
	"strings"
	"time"
)

// atomFeedLimit caps entries per fetch; feed readers keep their own history,
// so the subscription only needs the recent tail, not the whole snapshot.
const atomFeedLimit = 50

// atomFeed names one feed: its title, its own path, and the page it mirrors.
type atomFeed struct {
	Title string
	Path  string
	Page  string
}

var (
	malwareFeed = atomFeed{Title: "OpenHash: Malware", Path: "/malware.atom", Page: "/malware"}
	falloutFeed = atomFeed{Title: "OpenHash: Fallout", Path: "/fallout.atom", Page: "/fallout"}
)

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

// buildAtomFeed renders newest-first rows as Atom 1.0 for feed. base is the
// request origin ("https://sha256.is"); entry ids use the urn:sha256 form so
// they stay stable across hosts, reorderings, and the two feeds.
func buildAtomFeed(feed atomFeed, rows []feedRow, base string, now time.Time) ([]byte, error) {
	if len(rows) > atomFeedLimit {
		rows = rows[:atomFeedLimit]
	}
	updated := now
	if len(rows) > 0 {
		updated = rows[0].AnalyzedAt
	}
	doc := atomDoc{
		Xmlns:   "http://www.w3.org/2005/Atom", //nolint:revive // the Atom namespace is an identifier, not a URL; https is a different namespace
		Title:   feed.Title,
		ID:      base + feed.Page,
		Updated: updated.UTC().Format(time.RFC3339),
		Author:  atomAuthor{Name: "OpenHash"},
		Links: []atomLink{
			{Href: base + feed.Path, Rel: "self", Type: "application/atom+xml"},
			{Href: base + feed.Page, Rel: "alternate", Type: "text/html"},
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
			Link:    atomLink{Href: base + "/" + row.SHA256, Rel: "alternate", Type: "text/html"},
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

// handleMalwareAtom serves the Malware list: every known-bad sample, newest first.
func handleMalwareAtom(w http.ResponseWriter, r *http.Request) {
	if hopperStore.Load() == nil {
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}
	args := hostileListArgs(malwareList, false)
	snapshot, _, err := loadFeedSnapshot(r.Context(), &args, logger, false)
	if err != nil {
		logger.Warn("atom feed: snapshot unavailable", "feed", malwareFeed.Path, "error", err)
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}
	writeAtomFeed(w, r, malwareFeed, feedRowsFromSnapshot(snapshot))
}

// handleFalloutAtom serves the week in progress, through the same gate as the
// Fallout page and its JSON, one entry per catch. The week is cut in UTC: a
// feed has no reader's zone, and entry ids carry over a week's turn anyway.
func handleFalloutAtom(w http.ResponseWriter, r *http.Request) {
	if hopperStore.Load() == nil {
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	week := falloutWeekOf(now, now)
	args := week.snapshotArgs()
	snapshot, _, err := loadFeedSnapshot(r.Context(), &args, logger, false)
	if err != nil {
		logger.Warn("atom feed: snapshot unavailable", "feed", falloutFeed.Path, "error", err)
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
		return
	}
	rows := falloutRowsInWindow(feedRowsFromSnapshot(snapshot), week, falloutAny)
	writeAtomFeed(w, r, falloutFeed, rows)
}

// handleLegacyAtom keeps subscriptions to the old single feed alive: it was
// the Malware list, so that is where it now points.
func handleLegacyAtom(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, malwareFeed.Path, http.StatusMovedPermanently)
}

func writeAtomFeed(w http.ResponseWriter, r *http.Request, feed atomFeed, rows []feedRow) {
	out, err := buildAtomFeed(feed, rows, requestBaseURL(r), time.Now())
	if err != nil {
		logger.Error("atom feed: marshal failed", "feed", feed.Path, "error", err)
		http.Error(w, "feed unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/atom+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	body := append([]byte(xml.Header), out...)
	if _, err := w.Write(body); err != nil {
		logger.Debug("atom feed: write failed", "feed", feed.Path, "error", err)
	}
}
