package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nutsdb/nutsdb"
)

// resetLocalCacheDB closes the process-wide DB singleton so the next open binds
// to the current test's isolated HOME — and, critically, releases the DB's
// directory flock so spawned CLI child processes can open it themselves.
func resetLocalCacheDB(t *testing.T) {
	t.Helper()
	if cacheDB != nil {
		_ = cacheDB.Close()
	}
	cacheDB = nil
	dbOnce = sync.Once{}
	t.Cleanup(func() {
		if cacheDB != nil {
			_ = cacheDB.Close()
		}
		cacheDB = nil
		dbOnce = sync.Once{}
	})
}

func isolateLocalCache(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("JIRA_API_TOKEN", "")
	t.Setenv("JIRA_BASE_URL", "")
	resetLocalCacheDB(t)
}

// isolateSettings resets the settings singleton so a test can pin CLONES_*/XDG
// env vars before the first getSettings call and not leak config to siblings.
func isolateSettings(t *testing.T) {
	t.Helper()
	cachedSettings = nil
	settingsOnce = sync.Once{}
	t.Cleanup(func() {
		cachedSettings = nil
		settingsOnce = sync.Once{}
	})
}

func writeLocalCacheTestFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func getLocalReposTestRawValue(t *testing.T) []byte {
	t.Helper()
	db, err := getCacheDB()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	value, err := tx.Get(bucketLocalRepos, []byte(localReposSnapshotKey))
	if err != nil {
		t.Fatalf("local snapshot missing: %v", err)
	}
	return value
}

func getLocalReposTestSnapshot(t *testing.T) localReposSnapshot {
	t.Helper()
	var snapshot localReposSnapshot
	if err := json.Unmarshal(getLocalReposTestRawValue(t), &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func putLocalReposTestValue(t *testing.T, value []byte) {
	t.Helper()
	db, err := getCacheDB()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketLocalRepos); err != nil && !isBucketExistsErr(err) {
		t.Fatal(err)
	}
	if err := tx.Put(bucketLocalRepos, []byte(localReposSnapshotKey), value, 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// putLocalReposTestSnapshot writes a caller-controlled snapshot record (e.g. with a
// backdated SavedAt) the same way saveLocalReposCache stores it.
func putLocalReposTestSnapshot(t *testing.T, snapshot localReposSnapshot) {
	t.Helper()
	value, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	putLocalReposTestValue(t, value)
}

func TestLocalReposCacheRoundTrip(t *testing.T) {
	isolateLocalCache(t)
	want := []Repository{{
		Platform: "github", Owner: "owner", Name: "repo", LocalPath: "/projects/owner/repo",
		URL: "git@github.com:owner/repo.git", Description: "description",
		IsDirty: true, HasUnpushed: true, CurrentBranch: "feature/DEVOPS-123",
		JiraTicketID: "DEVOPS-123", JiraTicketIDs: []string{"DEVOPS-123", "DEVOPS-456"},
		JiraStatus: "In Progress", JiraSummary: "a ticket", HasActiveJiraTicket: true,
	}}
	if err := saveLocalReposCache("key", want); err != nil {
		t.Fatal(err)
	}
	if got, ok := loadLocalReposCache("key"); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip: hit=%v got=%+v", ok, got)
	}
	// Replacing a populated list with an empty list must not retain old entries.
	if err := saveLocalReposCache("key", nil); err != nil {
		t.Fatal(err)
	}
	if got, ok := loadLocalReposCache("key"); !ok || len(got) != 0 {
		t.Fatalf("empty list: hit=%v got=%+v", ok, got)
	}
	invalidateLocalReposCache()
	if _, ok := loadLocalReposCache("key"); ok {
		t.Fatal("invalidated snapshot was still a hit")
	}
	// Invalidating when nothing is stored is fine, not an error.
	invalidateLocalReposCache()
}

func TestLocalReposCacheMisses(t *testing.T) {
	isolateLocalCache(t)
	if _, ok := loadLocalReposCache("key"); ok {
		t.Fatal("missing snapshot was a hit")
	}
	cases := []struct {
		name   string
		mutate func(*localReposSnapshot)
	}{
		{"expired", func(s *localReposSnapshot) { s.SavedAt = time.Now().Add(-localCacheTTL) }},
		{"future timestamp", func(s *localReposSnapshot) { s.SavedAt = time.Now().Add(time.Hour) }},
		{"missing timestamp", func(s *localReposSnapshot) { s.SavedAt = time.Time{} }},
		{"wrong version", func(s *localReposSnapshot) { s.Version++ }},
		{"wrong context", func(s *localReposSnapshot) { s.Key = "other" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snapshot := localReposSnapshot{Version: localCacheVersion, Key: "key", SavedAt: time.Now()}
			c.mutate(&snapshot)
			putLocalReposTestSnapshot(t, snapshot)
			if _, ok := loadLocalReposCache("key"); ok {
				t.Fatal("invalid snapshot was a hit")
			}
		})
	}
	putLocalReposTestValue(t, []byte("{broken"))
	if _, ok := loadLocalReposCache("key"); ok {
		t.Fatal("corrupt snapshot was a hit")
	}
}

func TestLocalReposCacheContext(t *testing.T) {
	isolateLocalCache(t)
	config := JiraConfig{Enabled: true, Token: "file-secret", BaseURL: "https://jira.example", Email: "a@example", JQL: "assignee = currentUser()"}
	key := localReposCacheKey("/projects", &config)
	if other := localReposCacheKey("/other", &config); other == key {
		t.Fatal("clone root did not affect the key")
	}
	cases := []struct {
		name   string
		mutate func(*JiraConfig)
	}{
		{"enabled", func(c *JiraConfig) { c.Enabled = false }},
		{"token", func(c *JiraConfig) { c.Token = "other" }},
		{"url", func(c *JiraConfig) { c.BaseURL = "https://other.example" }},
		{"account", func(c *JiraConfig) { c.Email = "b@example" }},
		{"jql", func(c *JiraConfig) { c.JQL = "project = OTHER" }},
		{"statuses", func(c *JiraConfig) { c.ActiveStatuses = []string{"Done"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			other := config
			c.mutate(&other)
			if localReposCacheKey("/projects", &other) == key {
				t.Fatal("Jira configuration change did not affect the key")
			}
		})
	}
	for _, env := range []string{"JIRA_API_TOKEN", "JIRA_BASE_URL"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "env-secret")
			other := localReposCacheKey("/projects", &config)
			if other == key {
				t.Fatal("Jira environment change did not affect the key")
			}
			if err := saveLocalReposCache(other, nil); err != nil {
				t.Fatal(err)
			}
			raw := string(getLocalReposTestRawValue(t))
			for _, secret := range []string{"file-secret", "env-secret", config.Email} {
				if strings.Contains(raw, secret) {
					t.Fatalf("snapshot record contains unhashed Jira credential %q", secret)
				}
			}
		})
	}
}

func TestGetCacheDBRecoversAfterDirUnlock(t *testing.T) {
	isolateLocalCache(t)
	cacheDir, err := getCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	options := nutsdb.DefaultOptions
	options.Dir = filepath.Join(cacheDir, "db")
	holder, err := nutsdb.Open(options)
	if err != nil {
		t.Fatal("expected holder open to succeed:", err)
	}
	if _, err := getCacheDB(); err == nil || !errors.Is(err, nutsdb.ErrDirLocked) {
		t.Fatalf("want ErrDirLocked, got %v", err)
	}
	_ = holder.Close()
	db, err := getCacheDB()
	if err != nil || db == nil {
		t.Fatalf("did not recover after unlock: db=%v err=%v", db, err)
	}
}

func TestLocalReposCacheInvalidationRetriesWhenLocked(t *testing.T) {
	isolateLocalCache(t)
	localInvalidationRetryWindow = 900 * time.Millisecond
	t.Cleanup(func() { localInvalidationRetryWindow = 2 * time.Second })

	cacheDir, err := getCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	options := nutsdb.DefaultOptions
	options.Dir = filepath.Join(cacheDir, "db")
	holder, err := nutsdb.Open(options)
	if err != nil {
		t.Fatal("expected holder open to succeed:", err)
	}
	// Seed the snapshot from the lock-holder "process", like a concurrent clone of ours would.
	value, _ := json.Marshal(localReposSnapshot{Version: localCacheVersion, Key: "key", SavedAt: time.Now(), Repos: []Repository{{Name: "old"}}})
	if err := holder.Update(func(tx *nutsdb.Tx) error {
		if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketLocalRepos); err != nil && !isBucketExistsErr(err) {
			return err
		}
		return tx.Put(bucketLocalRepos, []byte(localReposSnapshotKey), value, 0)
	}); err != nil {
		t.Fatal(err)
	}

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = holder.Close()
	}()

	invalidateLocalReposCache() // must retry until the holder releases, then delete
	if _, ok := loadLocalReposCache("key"); ok {
		t.Fatal("snapshot survived a successful invalidation")
	}
}

func TestToRemotePathWithRelativeCloneRoot(t *testing.T) {
	isolateLocalCache(t)
	isolateSettings(t)
	configDir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "clones")
	writeLocalCacheTestFile(t, filepath.Join(configDir, "clones.yml"),
		"remote:\n  host: test-host\n  path: /srv/projects\n  ops:\n    - pull\n", 0600)
	t.Setenv("CLONES_ROOT", "projects")

	s := getSettings()
	if !filepath.IsAbs(s.CloneRoot) {
		t.Fatalf("clone root was not normalized to an absolute path: %q", s.CloneRoot)
	}
	remotePath, err := toRemotePath(filepath.Join(s.CloneRoot, "owner", "repo"))
	if err != nil {
		t.Fatalf("remote mapping failed with normalized root: %v", err)
	}
	if want := "/srv/projects/owner/repo"; remotePath != want {
		t.Fatalf("remote path: got %q want %q", remotePath, want)
	}
}

// Run the real CLI in a fresh process, with noninteractive fzf and git test doubles.
// This tests disk persistence and flag plumbing rather than in-process memoization.
func TestLocalCacheCLIProcess(t *testing.T) {
	if os.Getenv("CLONES_TEST_RUN_MAIN") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("CLONES_TEST_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"clones"}, args...)
	main()
	os.Exit(0)
}

func setupLocalCacheCLI(t *testing.T) string {
	t.Helper()
	isolateLocalCache(t)
	root := t.TempDir()
	bin := t.TempDir()
	t.Setenv("CLONES_ROOT", root)
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_ACCESS_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "")
	t.Setenv("GITLAB_ACCESS_TOKEN", "")
	t.Setenv("CLONES_TEST_GIT_LOG", filepath.Join(t.TempDir(), "git.log"))
	t.Setenv("CLONES_TEST_FZF_LOG", filepath.Join(t.TempDir(), "fzf.log"))
	t.Setenv("CLONES_TEST_BRANCH", "main")
	t.Setenv("CLONES_TEST_GIT_FAIL", "")
	// Restrict PATH to the doubles: no real git, gh, glab, or network discovery.
	t.Setenv("PATH", bin)
	writeLocalCacheTestFile(t, filepath.Join(bin, "git"), `#!/bin/sh
printf '%s\n' "$*" >> "$CLONES_TEST_GIT_LOG"
if [ "$CLONES_TEST_GIT_FAIL" = 1 ]; then exit 1; fi
case "$1" in
  config)
    case "$PWD" in
      */beta) printf 'git@gitlab.com:owner/beta.git\n' ;;
      *) printf 'git@github.com:owner/repo.git\n' ;;
    esac ;;
  status) printf ' M README.md\n' ;;
  rev-parse) printf '%s\n' "$CLONES_TEST_BRANCH" ;;
  log) printf 'abc an unpushed change\n' ;;
  branch) printf 'main\nfeature/DEVOPS-123\n' ;;
esac
`, 0755)
	writeLocalCacheTestFile(t, filepath.Join(bin, "fzf"), `#!/bin/sh
: > "$CLONES_TEST_FZF_LOG"
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$CLONES_TEST_FZF_LOG"
done
exit 1
`, 0755)
	// flake8: noqa - shell doubles above
	return root
}

func makeLocalCacheTestRepo(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, "owner", name)
	if err := os.MkdirAll(filepath.Join(path, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	writeLocalCacheTestFile(t, filepath.Join(path, "README.md"), "# Repo\nA cached description\n", 0644)
	return path
}

func runLocalCacheCLI(t *testing.T, args ...string) (string, time.Duration) {
	t.Helper()
	// Release the parent's DB flock so the child process can open the same DB dir.
	resetLocalCacheDB(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestLocalCacheCLIProcess$")
	cmd.Env = append(os.Environ(), "CLONES_TEST_RUN_MAIN=1", "CLONES_TEST_ARGS="+string(data))
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("CLI %v: %v\n%s", args, err, out)
	}
	rows, err := os.ReadFile(os.Getenv("CLONES_TEST_FZF_LOG"))
	if err != nil {
		t.Fatal(err)
	}
	return string(rows), elapsed
}

func localCacheGitCalls(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(os.Getenv("CLONES_TEST_GIT_LOG"))
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}

func TestLocalCacheCLIRepeatRunAndRefresh(t *testing.T) {
	root := setupLocalCacheCLI(t)
	makeLocalCacheTestRepo(t, root, "alpha")
	makeLocalCacheTestRepo(t, root, "beta")
	rows, cold := runLocalCacheCLI(t, "-l", "alpha")
	if !strings.Contains(rows, "owner/alpha") || strings.Contains(rows, "owner/beta") {
		t.Fatalf("cold filter: %q", rows)
	}
	calls := localCacheGitCalls(t)
	if calls == 0 {
		t.Fatal("cold listing did not scan repositories")
	}
	snapshot := getLocalReposTestSnapshot(t)
	if len(snapshot.Repos) != 2 {
		t.Fatal("first filtered run did not cache the complete list")
	}
	// Simulate reopening ten seconds later without slowing the test with a sleep.
	snapshot.SavedAt = time.Now().Add(-10 * time.Second)
	putLocalReposTestSnapshot(t, snapshot)
	t.Setenv("CLONES_TEST_BRANCH", "changed-externally")
	gamma := makeLocalCacheTestRepo(t, root, "gamma")
	rows, warm := runLocalCacheCLI(t, "-l", "beta", "--platform", "gitlab")
	if !strings.Contains(rows, "owner/beta") || strings.Count(rows, "\n") != 1 {
		t.Fatalf("warm filter/platform: %q", rows)
	}
	rows, _ = runLocalCacheCLI(t, "-l")
	if strings.Count(rows, "\n") != 2 || strings.Contains(rows, "owner/gamma") {
		t.Fatalf("warm list was rescanned: %q", rows)
	}
	if got := localCacheGitCalls(t); got != calls {
		t.Fatalf("cache hits ran git: calls before=%d after=%d", calls, got)
	}
	t.Logf("separate CLI processes: cold=%s, cached=%s; cached run used zero git commands", cold, warm)

	rows, _ = runLocalCacheCLI(t, "-l", "--no-cache")
	if strings.Count(rows, "\n") != 3 || !strings.Contains(rows, "owner/gamma") || localCacheGitCalls(t) <= calls {
		t.Fatalf("--no-cache did not rescan: %q", rows)
	}
	snapshot = getLocalReposTestSnapshot(t)
	for _, repo := range snapshot.Repos {
		if repo.CurrentBranch != "changed-externally" || !repo.IsDirty || !repo.HasUnpushed {
			t.Fatalf("full local state not refreshed: %+v", repo)
		}
	}
	calls = localCacheGitCalls(t)
	runLocalCacheCLI(t, "-l")
	if localCacheGitCalls(t) != calls {
		t.Fatal("--no-cache did not save a reusable fresh snapshot")
	}

	snapshot = getLocalReposTestSnapshot(t)
	snapshot.SavedAt = time.Now().Add(-localCacheTTL - time.Second)
	putLocalReposTestSnapshot(t, snapshot)
	if err := os.RemoveAll(gamma); err != nil {
		t.Fatal(err)
	}
	rows, _ = runLocalCacheCLI(t, "-l")
	if strings.Count(rows, "\n") != 2 || localCacheGitCalls(t) <= calls {
		t.Fatal("expiry did not trigger a rescan")
	}
	if fresh := getLocalReposTestSnapshot(t); len(fresh.Repos) != 2 {
		t.Fatal("expired snapshot was not replaced, keeping deleted repos")
	}
}

func TestLocalCacheCLISkipsJiraOnHit(t *testing.T) {
	root := setupLocalCacheCLI(t)
	makeLocalCacheTestRepo(t, root, "alpha")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"issues":[{"key":"DEVOPS-123","fields":{"summary":"A ticket","status":{"name":"In Progress"}}}]}`)
	}))
	defer server.Close()
	t.Setenv("JIRA_API_TOKEN", "test-token")
	t.Setenv("JIRA_BASE_URL", server.URL)
	configPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "clones", "jira.yml")
	writeLocalCacheTestFile(t, configPath, "enabled: true\nemail: test@example.com\njql: assignee = currentUser()\n", 0600)
	rows, _ := runLocalCacheCLI(t, "-l")
	if requests.Load() != 1 || !strings.Contains(rows, "DEVOPS-123") {
		t.Fatalf("cold Jira labels: requests=%d rows=%q", requests.Load(), rows)
	}
	calls := localCacheGitCalls(t)
	runLocalCacheCLI(t, "-l")
	if requests.Load() != 1 || localCacheGitCalls(t) != calls {
		t.Fatal("cache hit fetched Jira or ran git")
	}
	writeLocalCacheTestFile(t, configPath, "enabled: false\n", 0600)
	rows, _ = runLocalCacheCLI(t, "-l")
	if strings.Contains(rows, "DEVOPS-123") || localCacheGitCalls(t) <= calls {
		t.Fatal("Jira config change did not invalidate cached labels")
	}
}

func TestLocalCacheCLILargeMergedSnapshot(t *testing.T) {
	root := setupLocalCacheCLI(t)
	var repos []Repository
	for i := 0; i < 600; i++ {
		repos = append(repos, Repository{Owner: "owner", Name: fmt.Sprintf("repo-%d", i), Platform: "github", LocalPath: filepath.Join(root, "owner", fmt.Sprintf("repo-%d", i))})
	}
	key := localReposCacheKey(root, &JiraConfig{})
	if err := saveLocalReposCache(key, repos); err != nil {
		t.Fatal(err)
	}
	rows, _ := runLocalCacheCLI(t)
	if strings.Count(rows, "\n") != 600 || localCacheGitCalls(t) != 0 {
		t.Fatalf("merged mode: got %d rows, %d git calls; want 600 rows and no git calls", strings.Count(rows, "\n"), localCacheGitCalls(t))
	}
}

func TestLocalCacheCLICacheFailureStillLists(t *testing.T) {
	root := setupLocalCacheCLI(t)
	makeLocalCacheTestRepo(t, root, "alpha")
	// A regular file where the DB directory belongs makes the cache DB unusable —
	// the listing must silently degrade to a full scan.
	home := os.Getenv("HOME")
	cacheDir := filepath.Join(home, ".cache", "clones")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "db"), []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	rows, _ := runLocalCacheCLI(t, "-l")
	if !strings.Contains(rows, "owner/alpha") {
		t.Fatal("cache failure prevented listing")
	}
}

func TestLocalCacheMutationInvalidation(t *testing.T) {
	root := setupLocalCacheCLI(t)
	isolateSettings(t)
	repo := makeLocalCacheTestRepo(t, root, "alpha")
	cases := []struct {
		name string
		fail bool
		run  func() error
	}{
		{"checkout", false, func() error { return runGitInRepo("checkout", repo, "checkout", "main") }},
		{"failed checkout", true, func() error { return runGitInRepo("checkout", repo, "checkout", "main") }},
		{"clone", false, func() error { return runClone("clone", filepath.Join(root, "owner", "new"), "main", "test-url") }},
		{"failed clone", true, func() error { return runClone("clone", filepath.Join(root, "owner", "new"), "main", "test-url") }},
		{"delete", false, func() error { return runRemove("delete", repo) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := saveLocalReposCache("key", []Repository{{Name: "old"}}); err != nil {
				t.Fatal(err)
			}
			if c.fail {
				t.Setenv("CLONES_TEST_GIT_FAIL", "1")
			}
			err := c.run()
			if (err != nil) != c.fail {
				t.Fatalf("mutation error=%v, want failure=%v", err, c.fail)
			}
			if _, ok := loadLocalReposCache("key"); ok {
				t.Fatal("mutation left a usable old snapshot")
			}
		})
	}
}
