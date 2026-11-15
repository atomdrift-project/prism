package main

import (
	"slices"
	"testing"
)

func TestPackageSearchPURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"litellm", []string{"pkg:pypi/litellm", "pkg:conda/litellm", "pkg:alpm/arch/litellm"}},
		{"@scope/pkg", []string{"pkg:npm/%40scope/pkg"}},
		{"my_project", []string{"pkg:pypi/my-project"}},
		{"vendor/package", []string{"pkg:composer/vendor/package"}},
		{"org.example:library", []string{"pkg:maven/org.example/library"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := packageSearchPURLs(tc.name, []string{"python", "pypi", "conda", "arch"}, []string{"pythonhosted.org"})
			for _, purl := range tc.want {
				if !slices.Contains(got, purl) {
					t.Errorf("missing identity %q in %v", purl, got)
				}
			}
			if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
				t.Fatalf("candidates must be sorted and unique: %v", got)
			}
		})
	}
	for _, term := range []string{"", "two words", "line\nbreak"} {
		if got := packageSearchPURLs(term, nil, nil); len(got) != 0 {
			t.Errorf("free text %q produced identities %v", term, got)
		}
	}
}
