package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nutsdb/nutsdb"
)

const (
	localCacheTTL         = time.Minute
	localCacheVersion     = 1
	localReposSnapshotKey = "local_repos_snapshot"
)

// localInvalidationRetryWindow bounds how long invalidation waits when another
// clones process holds the cache DB's directory lock, before giving up and
// leaving the snapshot to expire on its own (≤1 minute staleness, documented).
var localInvalidationRetryWindow = 2 * time.Second

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
// or unopenable DB, and missing, corrupt, incompatible and expired snapshots
// are misses — the caller rescans and rebuilds. An empty repository list is a
// valid cache hit.
func loadLocalReposCache(key string) ([]Repository, bool) {
	db, err := getCacheDB()
	if err != nil {
		// Another clones process holds the DB; degrading to a full scan is correct.
		return nil, false
	}

	tx, err := db.Begin(false)
	if err != nil {
		return nil, false
	}
	defer func() { _ = tx.Rollback() }()

	value, err := tx.Get(bucketLocalRepos, []byte(localReposSnapshotKey))
	if err != nil {
		return nil, false
	}

	var snapshot localReposSnapshot
	if err := json.Unmarshal(value, &snapshot); err != nil {
		return nil, false
	}

	now := time.Now()
	if snapshot.Version != localCacheVersion || snapshot.Key != key ||
		snapshot.SavedAt.After(now) || now.Sub(snapshot.SavedAt) >= localCacheTTL {
		return nil, false
	}
	return snapshot.Repos, true
}

// saveLocalReposCache stores the whole snapshot as a single NutsDB record — one
// upsert replaces the previous batch, so deleted repos drop out, and no
// obsolete rows linger (unlike per-repo upserts).
func saveLocalReposCache(key string, repos []Repository) error {
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
	if err := tx.Put(bucketLocalRepos, []byte(localReposSnapshotKey), value, 0); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not store local snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not commit tx: %w", err)
	}
	return nil
}

// invalidateLocalReposCache drops the snapshot so the next listing rescans.
// Mutating operations call this up front — even a partially failed operation
// may change state. If another clones process briefly holds the DB lock, retry
// within the window; past it, warn and let the snapshot expire.
func invalidateLocalReposCache() {
	deadline := time.Now().Add(localInvalidationRetryWindow)
	var err error
	for {
		err = deleteLocalReposSnapshot()
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

func deleteLocalReposSnapshot() error {
	db, err := getCacheDB()
	if err != nil {
		return err
	}
	tx, err := db.Begin(true)
	if err != nil {
		return err
	}
	if err := tx.Delete(bucketLocalRepos, []byte(localReposSnapshotKey)); err != nil {
		_ = tx.Rollback()
		if isNothingStoredErr(err) {
			return nil // nothing was cached — already invalidated
		}
		return err
	}
	return tx.Commit()
}
