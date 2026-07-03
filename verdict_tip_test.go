package main

import "testing"

func TestVerdictTip(t *testing.T) {
	ptr := func(n int) *int { return &n }
	tests := []struct {
		name       string
		level      *int
		pct        int
		finalClass string
		rawClass   *int
		llm        llmInterpretation
		want       string
	}{
		{
			name: "benign level renders no badge", level: ptr(-1), pct: 0,
			finalClass: "benign", want: "",
		},
		{
			name: "nil level renders no badge", level: nil, pct: 80,
			finalClass: "suspicious", want: "",
		},
		{
			name: "no llm pass states the level", level: ptr(250), pct: 80,
			finalClass: "suspicious", rawClass: nil,
			want: "[L250] 80% confident suspicious (lower levels are stricter)",
		},
		{
			name: "agreement states the level", level: ptr(100), pct: 90,
			finalClass: "hostile", rawClass: ptr(2),
			llm:  llmInterpretation{Grade: "hostile", Outcome: "hostile"},
			want: "[L100] 90% confident hostile (lower levels are stricter)",
		},
		{
			name: "safety-valve downgrade names the disagreement", level: ptr(250), pct: 80,
			finalClass: "suspicious", rawClass: ptr(2),
			llm:  llmInterpretation{Grade: "benign", Outcome: "suspicious"},
			want: "[L250] ML rated as hostile, LLM downgraded to suspicious",
		},
		{
			name: "escalation names the disagreement", level: ptr(100), pct: 85,
			finalClass: "hostile", rawClass: ptr(0),
			llm:  llmInterpretation{Grade: "hostile", Outcome: "hostile"},
			want: "[L100] ML rated as benign, LLM escalated to hostile",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := verdictTip(tc.level, tc.pct, tc.finalClass, tc.rawClass, tc.llm)
			if got != tc.want {
				t.Errorf("verdictTip = %q, want %q", got, tc.want)
			}
		})
	}
}
