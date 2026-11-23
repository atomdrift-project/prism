package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// beamlineServing points the Beamline client at a test server answering every
// request with handler.
func beamlineServing(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	oldAddr, oldClient := beamlineAPIAddr, beamlineClient
	t.Cleanup(func() { beamlineAPIAddr, beamlineClient = oldAddr, oldClient })
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	beamlineAPIAddr, beamlineClient = srv.URL, &http.Client{}
}

// TestAnalyzeWithBeamline replays a stream Beamline answered a zip upload
// with: two progress frames, then scan's full result.
func TestAnalyzeWithBeamline(t *testing.T) {
	stream, err := os.ReadFile("testdata/beamline-full-zip.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	beamlineServing(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/analyze" {
			t.Errorf("path = %q, want /v1/analyze", r.URL.Path)
		}
		if got := r.URL.Query().Get("full"); got != "1" {
			t.Errorf("full query = %q, want 1", got)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		} else if string(got) != "PAYLOAD" {
			t.Errorf("body = %q, want PAYLOAD", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("content type = %q, want application/octet-stream", got)
		}
		if got := r.Header.Get("X-Filename"); got != "fixture.zip" {
			t.Errorf("X-Filename = %q, want fixture.zip", got)
		}
		w.Header().Set("X-Beamline-Worker", "scan-test")
		w.Header().Set("X-Beamline-Source", "scan:analysis")
		if _, err := w.Write(stream); err != nil {
			t.Errorf("write response: %v", err)
		}
	})

	var frames []string
	accepted := false
	result, err := analyzeWithBeamline(context.Background(), []byte("PAYLOAD"), "fixture.zip", func(frame []byte) {
		frames = append(frames, string(frame))
	}, func() { accepted = true })
	if err != nil {
		t.Fatalf("analyzeWithBeamline: %v", err)
	}
	if !accepted {
		t.Error("onAccepted was not called")
	}
	if result.Server != "scan-test" || result.Source != "scan:analysis" {
		t.Errorf("server %q source %q, want scan-test and scan:analysis", result.Server, result.Source)
	}
	lines := strings.SplitAfter(string(stream), "\n")
	if want := strings.Join(lines[2:], ""); string(result.Body) != want {
		t.Errorf("body = %.200q…, want the stream from its v8 header on", result.Body)
	}
	if len(frames) != 2 || !strings.Contains(frames[0], `"state":"analyzing"`) || !strings.Contains(frames[1], `"phase_state":"completed"`) {
		t.Errorf("frames = %q, want only the two progress frames", frames)
	}
}

// TestAnalyzeWithBeamlineWithoutResult covers streams that end without a full
// result: Beamline's own unavailable row, scan's unavailable decision, and a
// stream cut short. None may be taken for an analysis.
func TestAnalyzeWithBeamlineWithoutResult(t *testing.T) {
	progress := `{"state":"analyzing","elapsed_ms":1002,"phase":"fetch"}` + "\n"
	for _, tc := range []struct {
		name, stream, want string
	}{
		{"beamline unavailable", progress + `{"status":"unavailable","cause":"unreachable","severity":"unknown","findings":[]}` + "\n", `"cause":"unreachable"`},
		{"scan unavailable", progress + `{"decision":"unavailable","reason":"analysis timed out"}` + "\n", "analysis timed out"},
		{"cut short", progress, "ended without a full result"},
		{"not json", progress + "<html>bad gateway</html>\n", "decode beamline frame"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beamlineServing(t, func(w http.ResponseWriter, _ *http.Request) {
				if _, err := io.WriteString(w, tc.stream); err != nil {
					t.Errorf("write response: %v", err)
				}
			})
			var frames [][]byte
			result, err := analyzeWithBeamline(context.Background(), []byte("PAYLOAD"), "sample.bin", func(frame []byte) {
				frames = append(frames, bytes.Clone(frame))
			}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("result %+v, error %v; want an error mentioning %q", result, err, tc.want)
			}
			if len(frames) != 1 {
				t.Errorf("frames = %q, want the one progress frame", frames)
			}
		})
	}
}
