package main

import (
	"encoding/json"
	"sync"
	"time"
)

// uploadEventStream keeps the short-lived Beamline transcript for one browser
// upload. It is deliberately in-memory: the transcript is UI telemetry, not
// the analysis result, and Hopper remains authoritative for the final page.
//
//nolint:govet // the mutex stays adjacent to the mutable progress state.
type uploadEventStream struct {
	mu          sync.Mutex
	closed      bool
	events      [][]byte
	subscribers map[chan []byte]struct{}
}

//nolint:govet // this short-lived handoff keeps the subscription self-contained.
type uploadEventSubscription struct {
	closed      bool
	history     [][]byte
	events      <-chan []byte
	unsubscribe func()
}

const maxUploadStreamEvents = 64

func newUploadEventStream() *uploadEventStream {
	return &uploadEventStream{subscribers: make(map[chan []byte]struct{})}
}

func (s *uploadEventStream) publish(frame []byte) {
	if !json.Valid(frame) {
		return
	}
	if len(frame) > 64<<10 {
		frame = frame[:64<<10]
	}
	copyFrame := append([]byte(nil), frame...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if len(s.events) == maxUploadStreamEvents {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = copyFrame
	} else {
		s.events = append(s.events, copyFrame)
	}
	for sub := range s.subscribers {
		select {
		case sub <- append([]byte(nil), copyFrame...):
		default:
			// A slow browser already has enough history to catch up. Do not let
			// it hold Beamline's analysis goroutine hostage.
		}
	}
}

func (s *uploadEventStream) subscribe() uploadEventSubscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	history := make([][]byte, len(s.events))
	for i := range s.events {
		history[i] = append([]byte(nil), s.events[i]...)
	}
	if s.closed {
		return uploadEventSubscription{history: history, unsubscribe: func() {}, closed: true}
	}
	sub := make(chan []byte, 16)
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
	time.AfterFunc(uploadFailureTTL, func() { uploadEventStreams.Delete(sha) })
	return stream
}
