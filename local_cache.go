package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nutsdb/nutsdb"
)

const (
	// localCacheRefreshThreshold is how old a served snapshot may be before a
	// run opportunistically rescans in the background for the NEXT one.
	// Snapshots are served instantly no matter their age (serve-stale): there
	// is no hard expiry. First-ever runs and --no-cache scan synchronously.
	localCacheRefreshThreshold = time.Minute

	// localCacheVersion 2: v1.2.0 switched the scan to leaf-walk, which
	// excludes repos nested inside other repos. Snapshots written before then
	// are discarded once on first run and rebuilt from the new scan.
	localCacheVersion     = 2
	localReposSnapshotKey = "local_repos_snapshot"

	// localReposEpochKey is the bucketMeta key holding a monotonic counter.
	// Every invalidating mutation bumps it inside the same transaction that
	// deletes the snapshot; a snapshot save must carry the epoch it was scanned
	// under and abort if the epoch moved — an in-flight refresh can never
	// resurrect a world an operation just invalidated (e.g. a deleted repo).
	localReposEpochKey = "local_repos_epoch"
)

// errLocalSnapshotEpochAdvanced is returned by saveLocalReposCache when the
// cache epoch moved between the scan and the save: the caller's results
// describe a world an invalidating operation has since changed, so they are
// dropped silently.
var errLocalSnapshotEpochAdvanced = errors.New("local cache epoch advanced; dropping scan results")

// localInvalidationRetryWindow bounds how long invalidation waits when another
// clones process holds the cache DB's directory lock, before giving up and
// warning. Under serve-stale caching there is no TTL backstop: a failed
// invalidation leaves the stale snapshot served until a later run succeeds,
// so failures stay loud.
var localInvalidationRetryWindow = 2 * time.Second

// Background refresh lifecycle: findLocalRepos registers at most one tracked
// goroutine per process — the refresh for a served snapshot older than
// localCacheRefreshThreshold. Exit paths wait for it so the next run starts
// fresh; invalidating ops void any in-flight refresh via the epoch guard and
// raise localRefreshAbandoned, so those waits return instantly.
var (
	localRefreshWG        sync.WaitGroup
	localRefreshAbandoned atomic.Bool
)

// registerLocalRefresh starts fn in a tracked goroutine. findLocalRepos
// registers strictly before serving any snapshot row, so every later Wait
// happens after the matching Add — no WaitGroup Add/Wait race is possible.
func registerLocalRefresh(fn func()) {
	localRefreshWG.Add(1)
	go func() {
		defer localRefreshWG.Done()
		fn()
	}()
}

// waitForLocalRefresh blocks exit paths until in-flight background refreshes
// finish persisting. Instant when none was registered, or when an invalidating
// op abandoned the refresh (its save would be dropped anyway).
func waitForLocalRefresh() {
	if localRefreshAbandoned.Load() {
		return
	}
	localRefreshWG.Wait()
}

type localReposSnapshot struct {
	Version int          `json:"version"`
	Key     string       `json:"key"`
	SavedAt time.Time    `json:"saved_at"`
	Repos   []Repository `json:"repos"`
}

// localReposCacheKey scopes the snapshot to the absolute clone root and Jira
// configuration. Credentials affect the key but are never written to the DB.
func localReposCacheKey(workDir string, jiraConfig *JiraConfig) string {
	data, _ := json.Marshal(struct {
		Root        string
		Jira        *JiraConfig
		JiraToken   string
		JiraBaseURL string
	}{workDir, jiraConfig, os.Getenv("JIRA_API_TOKEN"), os.Getenv("JIRA_BASE_URL")})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// loadLocalReposCache reads the persisted local snapshot from NutsDB. A locked
// or unopenable DB, and missing, corrupt, incompatible snapshots are misses —
// the caller rescans and rebuilds. AGE IS NOT A MISS: a valid snapshot is
// served no matter how old (serve-stale); the returned age lets the caller
// decide whether a background refresh is worth starting. An empty repository
// list is a valid cache hit.
func loadLocalReposCache(key string) ([]Repository, time.Duration, bool) {
	db, err := getCacheDB()
	if err != nil {
		// Another clones process holds the DB; degrading to a full scan is correct.
		return nil, 0, false
	}

	tx, err := db.Begin(false)
	if err != nil {
		return nil, 0, false
	}
	defer func() { _ = tx.Rollback() }()

	value, err := tx.Get(bucketLocalRepos, []byte(localReposSnapshotKey))
	if err != nil {
		return nil, 0, false
	}

	var snapshot localReposSnapshot
	if err := json.Unmarshal(value, &snapshot); err != nil {
		return nil, 0, false
	}

	now := time.Now()
	if snapshot.Version != localCacheVersion || snapshot.Key != key ||
		snapshot.SavedAt.IsZero() || snapshot.SavedAt.After(now) {
		return nil, 0, false
	}
	return snapshot.Repos, now.Sub(snapshot.SavedAt), true
}

// saveLocalReposCache stores the whole snapshot as a single NutsDB record in
// ONE transaction that re-checks the cache epoch first: if any invalidating
// mutation ran since expectedEpoch was captured (at scan start), the save is
// dropped — the results being saved may describe an already-invalidated world
// (e.g. a repo deleted mid-scan must not reappear).
func saveLocalReposCache(expectedEpoch int64, key string, repos []Repository) error {
	value, err := json.Marshal(localReposSnapshot{
		Version: localCacheVersion,
		Key:     key,
		SavedAt: time.Now(),
		Repos:   repos,
	})
	if err != nil {
		return err
	}

	db, err := getCacheDB()
	if err != nil {
		return fmt.Errorf("could not open cache db: %w", err)
	}

	tx, err := db.Begin(true)
	if err != nil {
		return fmt.Errorf("could not begin tx: %w", err)
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketLocalRepos); err != nil && !isBucketExistsErr(err) {
		_ = tx.Rollback()
		return fmt.Errorf("could not create bucket %s: %w", bucketLocalRepos, err)
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketMeta); err != nil && !isBucketExistsErr(err) {
		_ = tx.Rollback()
		return fmt.Errorf("could not create bucket %s: %w", bucketMeta, err)
	}
	epoch, err := currentEpochInTx(tx)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not read cache epoch: %w", err)
	}
	if epoch != expectedEpoch {
		_ = tx.Rollback()
		return errLocalSnapshotEpochAdvanced
	}
	if err := tx.Put(bucketLocalRepos, []byte(localReposSnapshotKey), value, 0); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not store local snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not commit tx: %w", err)
	}
	return nil
}

// invalidateLocalReposCache drops the snapshot and bumps the cache epoch in a
// single transaction, voiding any in-flight refresh (whose save will fail the
// epoch re-check). Mutating operations call this up front — even a partially
// failed operation may change state. If another clones process briefly holds
// the DB lock, retry within the window; past it, warn loudly: without a TTL
// backstop the snapshot keeps being served until a later run invalidates.
func invalidateLocalReposCache() {
	localRefreshAbandoned.Store(true)
	deadline := time.Now().Add(localInvalidationRetryWindow)
	var err error
	for {
		err = deleteSnapshotAndBumpEpoch()
		if err == nil || !errors.Is(err, nutsdb.ErrDirLocked) {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to invalidate local cache: %v\n", err)
	}
}

// deleteSnapshotAndBumpEpoch is the invalidation transaction: drop the stored
// snapshot (idempotently) and increment the epoch counter, atomically.
func deleteSnapshotAndBumpEpoch() error {
	db, err := getCacheDB()
	if err != nil {
		return err
	}
	tx, err := db.Begin(true)
	if err != nil {
		return err
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketMeta); err != nil && !isBucketExistsErr(err) {
		_ = tx.Rollback()
		return fmt.Errorf("could not create bucket %s: %w", bucketMeta, err)
	}
	if err := tx.Delete(bucketLocalRepos, []byte(localReposSnapshotKey)); err != nil && !isNothingStoredErr(err) {
		_ = tx.Rollback()
		return err
	}
	epoch, err := currentEpochInTx(tx)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not read cache epoch: %w", err)
	}
	if err := tx.Put(bucketMeta, []byte(localReposEpochKey), []byte(fmt.Sprintf("%d", epoch+1)), 0); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not bump cache epoch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// currentEpochInTx reads the local cache epoch counter inside an open
// transaction. A missing counter is epoch 0, not an error.
func currentEpochInTx(tx *nutsdb.Tx) (int64, error) {
	value, err := tx.Get(bucketMeta, []byte(localReposEpochKey))
	if isNothingStoredErr(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(string(value), 10, 64)
}

// readLocalReposEpoch reports the current cache epoch for a scan that is about
// to start: the scan's results are only saved if the epoch still matches when
// the scan finishes (see saveLocalReposCache).
func readLocalReposEpoch() (int64, error) {
	db, err := getCacheDB()
	if err != nil {
		return 0, err
	}
	tx, err := db.Begin(false)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	return currentEpochInTx(tx)
}
