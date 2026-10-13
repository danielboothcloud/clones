package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nutsdb/nutsdb"
)

const (
	cacheTTLHours    = 24
	bucketGitHub     = "github_repos"
	bucketGitLab     = "gitlab_repos"
	bucketMeta       = "metadata"
	bucketLocalRepos = "local_repos"
)

// Database singleton for repository caching
var (
	cacheDB    *nutsdb.DB
	cacheDBErr error
	dbOnce     sync.Once
)

// getCacheDB opens and returns the NutsDB database (singleton pattern)
func getCacheDB() (*nutsdb.DB, error) {
	dbOnce.Do(func() {
		cacheDir, err := getCacheDir()
		if err != nil {
			cacheDBErr = fmt.Errorf("failed to get cache dir: %w", err)
			return
		}

		dbPath := filepath.Join(cacheDir, "db")
		if err := os.MkdirAll(dbPath, 0755); err != nil {
			cacheDBErr = fmt.Errorf("failed to create db directory: %w", err)
			return
		}

		options := nutsdb.DefaultOptions
		options.Dir = dbPath
		options.SegmentSize = 256 * 1024 * 1024 // 256MB
		options.EnableHintFile = true
		options.EnableMergeV2 = true

		if db, err := nutsdb.Open(options); err != nil {
			cacheDBErr = fmt.Errorf("failed to open cache db: %w", err)
		} else {
			cacheDB = db
		}
	})
	if cacheDBErr != nil && errors.Is(cacheDBErr, nutsdb.ErrDirLocked) {
		// Another clones process is holding the DB's directory lock. Reset the
		// failed-open singleton so the NEXT call retries — lock holders usually
		// exit within seconds — while still reporting the failure to this caller.
		err := cacheDBErr
		cacheDB = nil
		cacheDBErr = nil
		dbOnce = sync.Once{}
		return nil, err
	}
	return cacheDB, cacheDBErr
}

// isBucketExistsErr reports whether err is the benign "bucket already exists"
// returned by NewBucket when the bucket was created in earlier runs.
func isBucketExistsErr(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "bucket already exists") ||
		strings.Contains(err.Error(), "already exist"))
}

// isNothingStoredErr reports whether err means "no such key or bucket" — nothing
// was stored, which for snapshot invalidation is success.
func isNothingStoredErr(err error) bool {
	return err != nil && (errors.Is(err, nutsdb.ErrKeyNotFound) ||
		errors.Is(err, nutsdb.ErrBucketNotFound) ||
		errors.Is(err, nutsdb.ErrBucketNotExist))
}

func serializeRepo(repo Repository) ([]byte, error) {
	return json.Marshal(repo)
}

func deserializeRepo(data []byte) (Repository, error) {
	var repo Repository
	err := json.Unmarshal(data, &repo)
	return repo, err
}

// loadReposFromDB loads cached repositories from NutsDB for given platform
func loadReposFromDB(platform string) []Repository {
	db, err := getCacheDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open cache db: %v\n", err)
		return []Repository{}
	}

	tx, err := db.Begin(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not begin tx: %v\n", err)
		return []Repository{}
	}
	defer func() { _ = tx.Rollback() }()

	var bucket string
	switch platform {
	case "github":
		bucket = bucketGitHub
	case "gitlab":
		bucket = bucketGitLab
	default:
		return []Repository{}
	}

	var repos []Repository
	_, entries, err := tx.GetAll(bucket)
	if err != nil {
		return []Repository{}
	}

	for _, value := range entries {
		if repo, err := deserializeRepo(value); err == nil {
			repos = append(repos, repo)
		}
	}

	return repos
}

// saveReposToDB saves repositories to NutsDB for given platform (upsert)
func saveReposToDB(platform string, repos []Repository) error {
	db, err := getCacheDB()
	if err != nil {
		return fmt.Errorf("could not open cache db: %w", err)
	}

	tx, err := db.Begin(true)
	if err != nil {
		return fmt.Errorf("could not begin tx: %w", err)
	}

	var bucket string
	switch platform {
	case "github":
		bucket = bucketGitHub
	case "gitlab":
		bucket = bucketGitLab
	default:
		_ = tx.Rollback()
		return fmt.Errorf("unknown platform: %s", platform)
	}

	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucket); err != nil && !isBucketExistsErr(err) {
		_ = tx.Rollback()
		return fmt.Errorf("failed to create bucket %s: %w", bucket, err)
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketMeta); err != nil && !isBucketExistsErr(err) {
		_ = tx.Rollback()
		return fmt.Errorf("failed to create bucket %s: %w", bucketMeta, err)
	}

	for _, repo := range repos {
		key := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
		value, err := serializeRepo(repo)
		if err != nil {
			continue
		}
		_ = tx.Put(bucket, []byte(key), value, 0)
	}

	timestampKey := fmt.Sprintf("%s:batch_timestamp", platform)
	_ = tx.Put(bucketMeta, []byte(timestampKey), []byte(fmt.Sprintf("%d", time.Now().Unix())), 0)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not commit tx: %w", err)
	}

	return nil
}

// isBatchStale checks if cached data exists but is expired
func isBatchStale(platform string) bool {
	db, err := getCacheDB()
	if err != nil {
		return false
	}

	tx, err := db.Begin(false)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback() }()

	timestampKey := fmt.Sprintf("%s:batch_timestamp", platform)
	value, err := tx.Get(bucketMeta, []byte(timestampKey))
	if err != nil {
		return false
	}

	timestamp, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return false
	}

	expiresAt := time.Unix(timestamp, 0).Add(time.Duration(cacheTTLHours) * time.Hour)
	return time.Now().After(expiresAt)
}

// getCacheDir returns the cache directory path, creating it if needed
func getCacheDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".cache", "clones")

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("could not create cache directory: %w", err)
	}

	return cacheDir, nil
}
