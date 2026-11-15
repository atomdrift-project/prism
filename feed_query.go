package main

import (
	"slices"
	"strings"

	"github.com/atomdrift-project/hopper/pkgparse"
)

// packageSearchPURLs tries the identities the catalog's registries would assign
// to this name. SourcePURLIdentity is the same resolver used at ingestion; no
// suffix scan or package-name index is needed. Include the language registries
// even when their last arrival is outside the ecosystem dropdown's window.
func packageSearchPURLs(name string, ecosystems, domains []string) []string {
	if name == "" || strings.ContainsAny(name, " \t\r\n") {
		return nil
	}
	var candidates []string
	add := func(ecosystem, domain string) {
		if purl, ok := pkgparse.SourcePURLIdentity(ecosystem, domain, name); ok {
			candidates = append(candidates, purl)
		}
	}
	for _, ecosystem := range []string{"npm", "pypi", "gem", "cargo", "golang", "maven", "nuget", "composer"} {
		add(ecosystem, "")
	}
	for _, ecosystem := range ecosystems {
		add(ecosystem, "")
	}
	for _, domain := range domains {
		add("", domain)
	}
	slices.Sort(candidates)
	return slices.Compact(candidates)
}
