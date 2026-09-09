package main

import (
	"encoding/json"
	"sync"
	"time"
)

// uploadEventStream keeps the short-lived Beamline transcript for one browser
// upload. It is deliberately in-memory: the transcript is UI telemetry; the
// terminal full response is persisted in Prism's result cache separately.
//
//nolint:govet // the mutex stays adjacent to the mutable progress state.
type uploadEventStream struct {
	mu          sync.Mutex
	closed      bool
	events      []uploadStreamEvent
	subscribers map[chan uploadStreamEvent]struct{}
}

type uploadStreamEvent struct {
	kind string
	data []byte
}

//nolint:govet // this short-lived handoff keeps the subscription self-contained.
type uploadEventSubscription struct {
	closed      bool
	history     []uploadStreamEvent
	events      <-chan uploadStreamEvent
	unsubscribe func()
}

const maxUploadStreamEvents = 64

const (
	maxUploadProgressFrame = 64 << 10
	uploadProgressTTL      = uploadIngestTimeout + 5*time.Minute
)

func newUploadEventStream() *uploadEventStream {
	return &uploadEventStream{subscribers: make(map[chan uploadStreamEvent]struct{})}
}

func (s *uploadEventStream) publish(frame []byte) {
	s.publishEvent("beamline", compactUploadProgressFrame(frame))
}

func (s *uploadEventStream) publishServer(info []byte) {
	s.publishEvent("server", info)
}

func (s *uploadEventStream) publishEvent(kind string, frame []byte) {
	if len(frame) == 0 {
		return
	}
	copyFrame := append([]byte(nil), frame...)
	event := uploadStreamEvent{kind: kind, data: copyFrame}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if len(s.events) == maxUploadStreamEvents {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = event
	} else {
		s.events = append(s.events, event)
	}
	for sub := range s.subscribers {
		select {
		case sub <- uploadStreamEvent{kind: kind, data: append([]byte(nil), copyFrame...)}:
		default:
			// A slow browser already has enough history to catch up. Do not let
			// it hold Beamline's analysis goroutine hostage.
		}
	}
}

func (s *uploadEventStream) subscribe() uploadEventSubscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	history := make([]uploadStreamEvent, len(s.events))
	for i, event := range s.events {
		history[i] = uploadStreamEvent{kind: event.kind, data: append([]byte(nil), event.data...)}
	}
	if s.closed {
		return uploadEventSubscription{history: history, unsubscribe: func() {}, closed: true}
	}
	sub := make(chan uploadStreamEvent, 16)
	s.subscribers[sub] = struct{}{}
	return uploadEventSubscription{history: history, events: sub, unsubscribe: func() {
		s.mu.Lock()
		delete(s.subscribers, sub)
		s.mu.Unlock()
	}}
}

func (s *uploadEventStream) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for sub := range s.subscribers {
		close(sub)
		delete(s.subscribers, sub)
	}
}

var uploadEventStreams sync.Map // sha256 -> *uploadEventStream

func keepUploadEventStream(sha string) *uploadEventStream {
	stream := newUploadEventStream()
	uploadEventStreams.Store(sha, stream)
	// The stream is only a progress view. Keep it long enough for a refresh
	// race, then discard it regardless of whether the browser stayed open.
	time.AfterFunc(uploadProgressTTL, func() { uploadEventStreams.CompareAndDelete(sha, stream) })
	return stream
}

// compactUploadProgressFrame keeps SSE memory bounded without ever slicing a
// JSON value in half. Most Beamline phase frames are tiny and pass through
// unchanged. A terminal frame can contain a large findings body; for the
// progress UI we retain only scalar status fields and the first three compact
// trait descriptions. The complete result is cached separately by ingestUpload.
func compactUploadProgressFrame(frame []byte) []byte {
	if !json.Valid(frame) {
		return nil
	}
	if len(frame) <= maxUploadProgressFrame {
		return append([]byte(nil), frame...)
	}
	var source map[string]json.RawMessage
	if err := json.Unmarshal(frame, &source); err != nil {
		return nil
	}
	compact := make(map[string]json.RawMessage)
	for _, key := range []string{
		"phase", "phase_state", "phase_elapsed_ms", "phase_started_at", "state", "stage", "status", "message", "msg", "detail",
		"description", "phase_message", "level", "severity", "classification",
		"verdict", "decision", "risk_level", "why", "sha", "sha256", "fires_at",
		"elapsed_ms", "total_elapsed_ms", "engine_version",
	} {
		if value := source[key]; len(value) > 0 && len(value) <= 4096 {
			compact[key] = value
		}
	}
	for _, key := range []string{"top_traits", "traits", "findings"} {
		if value := compactProgressTraits(source[key]); len(value) > 0 {
			compact[key] = value
		}
	}
	if ml := compactProgressML(source["ml"]); len(ml) > 0 {
		compact["ml"] = ml
	}
	out, err := json.Marshal(compact)
	if err != nil || len(out) > maxUploadProgressFrame {
		return []byte(`{"phase":"progress","message":"Beamline produced a large progress update."}`)
	}
	return out
}

func compactProgressTraits(raw json.RawMessage) json.RawMessage {
	var values []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil {
		return nil
	}
	if len(values) > 3 {
		values = values[:3]
	}
	for i, value := range values {
		if len(value) <= 4096 {
			continue
		}
		var trait map[string]json.RawMessage
		if json.Unmarshal(value, &trait) != nil {
			values[i] = json.RawMessage(`"large finding"`)
			continue
		}
		brief := make(map[string]json.RawMessage)
		for _, key := range []string{"trait", "name", "title", "description", "desc", "id"} {
			if field := trait[key]; len(field) > 0 && len(field) <= 2048 {
				brief[key] = field
			}
		}
		encoded, err := json.Marshal(brief)
		if err != nil {
			values[i] = json.RawMessage(`"large finding"`)
			continue
		}
		values[i] = encoded
	}
	out, err := json.Marshal(values)
	if err != nil {
		return nil
	}
	return out
}

func compactProgressML(raw json.RawMessage) json.RawMessage {
	var source map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &source) != nil {
		return nil
	}
	compact := make(map[string]json.RawMessage)
	for _, key := range []string{"level", "lvl", "severity", "classification", "verdict"} {
		if value := source[key]; len(value) > 0 && len(value) <= 1024 {
			compact[key] = value
		}
	}
	for _, key := range []string{"top_traits", "traits", "findings"} {
		if value := compactProgressTraits(source[key]); len(value) > 0 {
			compact[key] = value
		}
	}
	if len(compact) == 0 {
		return nil
	}
	out, err := json.Marshal(compact)
	if err != nil {
		return nil
	}
	return out
}
