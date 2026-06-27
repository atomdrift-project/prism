package main

import (
	"context"
	"errors"
	"testing"
)

// TestRequestRescanReadOnly locks the read-only guard: when prism is pointed at
// a replica (PRISM_READONLY), the rescan write path is refused before any DB
// access, so it can neither no-op against the replica nor conflict with
// replication. The guard runs ahead of the hopperDB load, so no database is
// needed here.
func TestRequestRescanReadOnly(t *testing.T) {
	prev := readOnlyMode
	readOnlyMode = true
	defer func() { readOnlyMode = prev }()

	err := requestRescan(context.Background(), "deadbeef")
	if !errors.Is(err, errReadOnlyReplica) {
		t.Fatalf("requestRescan in read-only mode = %v, want errReadOnlyReplica", err)
	}
}
