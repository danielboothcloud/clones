package main

import "testing"

// TestReadLocalReposEpochFreshDB pins the epoch-probe contract used by every
// scan: reading the epoch on a fresh (never-written) cache DB must report
// epoch 0 and NO error. nutsdb v1.1.0 view transactions surface a distinct
// ErrNotFoundBucket ("bucket not found") sentinel for never-created buckets —
// which isNothingStoredErr must tolerate, or first-ever invalidations fail.
func TestReadLocalReposEpochFreshDB(t *testing.T) {
	isolateLocalCache(t)

	epoch, err := readLocalReposEpoch()
	if err != nil {
		t.Fatalf("fresh-DB epoch probe must not error, got epoch=%d err=%v", epoch, err)
	}
	if epoch != 0 {
		t.Fatalf("fresh-DB epoch must be 0, got %d", epoch)
	}

	if err := saveLocalReposCache(epoch, "key", []Repository{{Name: "old"}}); err != nil {
		t.Fatal(err)
	}
	if epoch, err = readLocalReposEpoch(); err != nil || epoch != 0 {
		t.Fatalf("post-save epoch: want 0/nil, got %d/%v", epoch, err)
	}

	invalidateLocalReposCache()

	if epoch, err = readLocalReposEpoch(); err != nil || epoch != 1 {
		t.Fatalf("post-invalidate epoch: want 1/nil, got %d/%v", epoch, err)
	}
}
