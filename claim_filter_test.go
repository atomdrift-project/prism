package main

import "testing"

func TestClaimTokenFromSearchQuery(t *testing.T) {
	cases := []struct {
		in, key, value string
		ok             bool
	}{
		{"name:7-Zip", "name", "7-Zip", true},
		{"signer:Igor Pavlov", "signer", "Igor Pavlov", true}, // spaces consumed
		{"Name: tool", "name", "tool", true},                  // case-insensitive key
		{"signer:", "", "", false},
		{"7-Zip name:x", "", "", false}, // only a leading token is a filter
		{"lodash-4.17.21.tgz", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		key, value, ok := claimTokenFromSearchQuery(c.in)
		if key != c.key || value != c.value || ok != c.ok {
			t.Errorf("claimTokenFromSearchQuery(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, key, value, ok, c.key, c.value, c.ok)
		}
	}
}
