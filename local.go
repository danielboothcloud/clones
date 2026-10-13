package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// extractRepoFromPath extracts owner and name from a repository path.
// GitHub: ~/projects/work/octocat/Hello-World -> owner="octocat", name="Hello-World"
// GitLab: ~/projects/work/a/b/c/d/repo -> owner="a/b/c/d", name="repo"
func extractRepoFromPath(repoPath string, workDir string) (owner string, name string) {
	relPath, err := filepath.Rel(workDir, repoPath)
	if err != nil {
		return "", ""
	}

	parts := strings.Split(relPath, string(filepath.Separator))
	if len(parts) < 2 {
		return "", ""
	}

	name = parts[len(parts)-1]
	owner = strings.Join(parts[:len(parts)-1], "/")

	return owner, name
}

// getRemoteInfo gets remote URL from git config and detects platform
func getRemoteInfo(repoPath string) (url string, platform string) {
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", "git"
	}

	url = strings.TrimSpace(string(output))

	if strings.Contains(url, "github.com") {
		platform = "github"
	} else if strings.Contains(url, "gitlab.com") {
		platform = "gitlab"
	} else {
		platform = "git"
	}

	return url, platform
}

// getRepoDescription tries to get a description from README or git config
func getRepoDescription(repoPath string) string {
	readmePaths := []string{"README.md", "README", "readme.md", "readme"}
	for _, readme := range readmePaths {
		readmePath := filepath.Join(repoPath, readme)
		data, err := os.ReadFile(readmePath)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					return line
				}
			}
		}
	}

	cmd := exec.Command("git", "config", "--get", "description")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err == nil {
		desc := strings.TrimSpace(string(output))
		if desc != "" && desc != "Unnamed repository; edit this file 'description' to name the repository." {
			return desc
		}
	}

	return ""
}

// matchesFilter checks if a repository matches the filter string
func matchesFilter(repo *Repository, filter string) bool {
	if filter == "" {
		return true
	}

	filter = strings.ToLower(filter)
	return strings.Contains(strings.ToLower(repo.Owner), filter) ||
		strings.Contains(strings.ToLower(repo.Name), filter) ||
		strings.Contains(strings.ToLower(repo.Description), filter)
}

// isRepoDirty checks if a repository has uncommitted changes
func isRepoDirty(repoPath string) bool {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(output))) > 0
}

// hasUnpushedCommits checks if a repository has commits that haven't been pushed
func hasUnpushedCommits(repoPath string) bool {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "@{u}")
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		return false
	}

	cmd = exec.Command("git", "log", "@{u}..HEAD", "--oneline")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(output))) > 0
}

// getCurrentBranch gets the current branch name for a local repository
func getCurrentBranch(repoPath string) string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// getAllBranches gets all branch names for a local repository
func getAllBranches(repoPath string) []string {
	cmd := exec.Command("git", "branch", "-a", "--format=%(refname:short)")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	branches := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result []string
	seen := make(map[string]bool)

	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if branch == "" || branch == "HEAD" {
			continue
		}
		displayBranch := strings.TrimPrefix(branch, "origin/")
		if !seen[displayBranch] {
			seen[displayBranch] = true
			result = append(result, displayBranch)
		}
	}

	return result
}

// skipScanDirNames lists directory names the repo scan never descends into.
// Inside repos these are unreachable anyway (a repo is a leaf — collectRepoPaths
// skips its whole subtree); the list guards against bulky non-repo trees hanging
// in the clone root (a stray node_modules, venv, or build dir with no repo above
// it). Hidden directories are deliberately NOT skipped wholesale — they were
// walked before v1.2.0, and .archive/…-style roots should keep working.
var skipScanDirNames = map[string]bool{
	"node_modules": true,
	"__pycache__":  true,
	".terraform":   true,
	".venv":        true,
	"venv":         true,
	"target":       true,
	".cache":       true,
	".next":        true,
	"build":        true,
	"dist":         true,
	"Pods":         true,
}

// collectRepoPaths leaf-walks workDir and returns every directory that directly
// contains a .git/ subdirectory. walkFailed is true when any entry error was
// hit — callers must not persist a snapshot in that case (pre-v1.2.0 contract).
//
// Repos are leaves: finding .git/ terminates descent into that directory, so
// repo guts (node_modules, build output) are always skipped and repos nested
// inside other repos' subtrees are not collected. Group directories (no .git)
// keep descending, so nested GitLab layouts like work/a/b/c/repo still resolve.
// On a real clone root this cut the scan from ~62k directories (13.6s) to a few
// hundred (~12ms).
func collectRepoPaths(workDir string) (repos []string, walkFailed bool) {
	walkFailed = false
	err := filepath.WalkDir(workDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			walkFailed = true
			fmt.Fprintf(os.Stderr, "✗ Local scan could not read %s: %v\n", path, walkErr)
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if path != workDir && skipScanDirNames[d.Name()] {
			return filepath.SkipDir
		}
		if hasGitDir(path) {
			repos = append(repos, path)
			return filepath.SkipDir
		}
		return nil
	})
	return repos, walkFailed || err != nil
}

// hasGitDir reports whether dir itself contains a .git directory. A .git *file*
// (git worktrees, submodules) is deliberately not treated as a repo — the
// pre-v1.2.0 walk only matched real .git directories, and that parity is kept.
func hasGitDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && info.IsDir()
}

// findLocalRepos serves the local snapshot instantly whenever one exists,
// regardless of age (serve-stale). When the served snapshot is older than
// localCacheRefreshThreshold it also starts a background refresh for the NEXT
// run — the open fzf session always stays static. First-ever runs and
// --no-cache scan synchronously. Cache hits skip the directory walk, all git
// subprocesses, and Jira requests entirely.
func findLocalRepos(filter string, noCache bool, ch chan<- Repository) {
	jiraConfig, err := loadJiraConfig()
	if err != nil {
		jiraConfig = &JiraConfig{}
	}

	workDir, err := filepath.Abs(getSettings().CloneRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not resolve clone root: %v\n", err)
		return
	}
	cacheKey := localReposCacheKey(workDir, jiraConfig)
	if !noCache {
		if repos, age, ok := loadLocalReposCache(cacheKey); ok {
			// Register the refresh BEFORE serving any row: a consumer could
			// react to a served row (select, exit) and reach waitForLocalRefresh,
			// and the WaitGroup Add must strictly precede every Wait.
			if age >= localCacheRefreshThreshold {
				registerLocalRefresh(func() {
					refreshLocalSnapshot(workDir, jiraConfig, cacheKey)
				})
			}
			for _, repo := range repos {
				if matchesFilter(&repo, filter) {
					ch <- repo
				}
			}
			return
		}
	}

	if _, err := os.Stat(workDir); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not access directory %s: %v\n", workDir, err)
		return
	}

	repos, walkFailed := scanLocalRepos(workDir, jiraConfig, noCache)

	// Persist before offering selections: exiting fzf early must not lose the
	// cache. Store every repo, not only matches, so changing the filter reuses
	// the snapshot. The epoch guard may drop the save if an invalidating op
	// won the race — never persist a stale world.
	if !walkFailed {
		epoch, epochErr := readLocalReposEpoch()
		if epochErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open cache db to save snapshot: %v\n", epochErr)
		} else if err := saveLocalReposCache(epoch, cacheKey, repos); err != nil && !errors.Is(err, errLocalSnapshotEpochAdvanced) {
			fmt.Fprintf(os.Stderr, "Warning: failed to save local cache: %v\n", err)
		}
	}
	for _, repo := range repos {
		if matchesFilter(&repo, filter) {
			ch <- repo
		}
	}
}

// refreshLocalSnapshot rescans in the background and replaces the stored
// snapshot for the NEXT run; it never touches the interactive session that
// started it. The save is epoch-guarded: an invalidating operation during the
// scan voids the result (a delete cannot resurrect a repo). The refresh runs
// with caches enabled — it is exactly the mechanism that keeps future runs
// fast, so it reuses the persisted JQL result.
func refreshLocalSnapshot(workDir string, jiraConfig *JiraConfig, cacheKey string) {
	epoch, err := readLocalReposEpoch()
	if err != nil {
		// DB locked or unopenable: nothing to save under anyway. Next run retries.
		return
	}
	repos, walkFailed := scanLocalRepos(workDir, jiraConfig, false)
	if walkFailed {
		return
	}
	if err := saveLocalReposCache(epoch, cacheKey, repos); err != nil && !errors.Is(err, errLocalSnapshotEpochAdvanced) {
		fmt.Fprintf(os.Stderr, "Warning: failed to save local cache: %v\n", err)
	}
}

// scanLocalRepos gathers full repo state for the whole clone root: one JQL
// call plus a bounded worker pool running the per-repo git subprocesses.
// noCache flows through to the JQL lookup (L1+L2 bypass + live fetch). The
// bool result is walkFailed — callers must not persist a snapshot then.
func scanLocalRepos(workDir string, jiraConfig *JiraConfig, noCache bool) ([]Repository, bool) {
	// Single JQL call returns key+summary+status for every matching ticket — avoids one
	// extra HTTP call per repo. When JQL is unconfigured, jql.OK is false and we fall back
	// to per-ticket fetchJiraTicket below.
	var jql JiraJQLResult
	if jiraConfig.Enabled && jiraConfig.JQL != "" {
		jql = loadJiraTicketsByJQL(jiraConfig.JQL, noCache)
	}

	// Phase 1 (leaf-walk): collect repo paths only — no git subprocesses yet.
	// collectRepoPaths treats any directory containing .git as a leaf; this
	// replaces v1.2.0's full descent into every repo's contents.
	repoPaths, walkFailed := collectRepoPaths(workDir)

	// Phase 2: fan-out per-repo work (5+ git subprocesses each) to a bounded worker pool.
	// Capped to avoid fd exhaustion on macOS (default soft limit is often 256).
	workers := runtime.NumCPU() * 2
	if workers > 16 {
		workers = 16
	}
	if workers < 2 {
		workers = 2
	}

	jobs := make(chan string, len(repoPaths))
	for _, p := range repoPaths {
		jobs <- p
	}
	close(jobs)

	var repos []Repository
	var reposMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repoPath := range jobs {
				repo, ok := buildLocalRepo(repoPath, workDir, jiraConfig, jql)
				if !ok {
					continue
				}
				reposMu.Lock()
				repos = append(repos, repo)
				reposMu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Deterministic listing order — worker completion order varies run to run.
	sort.Slice(repos, func(i, j int) bool { return repos[i].LocalPath < repos[j].LocalPath })

	return repos, walkFailed
}

// buildLocalRepo gathers the full Repository state for a single local clone.
// Runs all git subprocesses + (when JQL is unset) the Jira ticket fetch for the primary ticket.
// Returns ok=false when the path doesn't decode into owner/name.
func buildLocalRepo(repoPath, workDir string, jiraConfig *JiraConfig, jql JiraJQLResult) (Repository, bool) {
	owner, name := extractRepoFromPath(repoPath, workDir)
	if owner == "" || name == "" {
		return Repository{}, false
	}

	url, platform := getRemoteInfo(repoPath)
	description := getRepoDescription(repoPath)
	isDirty := isRepoDirty(repoPath)
	hasUnpushed := hasUnpushedCommits(repoPath)
	currentBranch := getCurrentBranch(repoPath)
	allBranches := getAllBranches(repoPath)

	var jiraTicketID, jiraStatus, jiraSummary string
	var hasActiveJiraTicket bool
	var jiraTicketIDs []string

	if jiraConfig.Enabled {
		seenTickets := make(map[string]bool)

		for _, branch := range allBranches {
			ticketID := extractJiraTicketID(branch)
			if ticketID == "" || seenTickets[ticketID] {
				continue
			}
			if jql.OK {
				if _, ok := jql.Tickets[ticketID]; !ok {
					continue
				}
			}
			seenTickets[ticketID] = true
			jiraTicketIDs = append(jiraTicketIDs, ticketID)
			if jiraTicketID == "" {
				jiraTicketID = ticketID
			}
		}

		if jiraTicketID != "" {
			if jql.OK {
				if t := jql.Tickets[jiraTicketID]; t != nil {
					jiraStatus = t.Fields.Status.Name
					jiraSummary = t.Fields.Summary
					hasActiveJiraTicket = isActiveJiraStatus(jiraStatus)
				}
			} else {
				if t := fetchJiraTicket(jiraTicketID); t != nil {
					jiraStatus = t.Fields.Status.Name
					jiraSummary = t.Fields.Summary
					hasActiveJiraTicket = isActiveJiraStatus(jiraStatus)
				}
			}
		}
	}

	return Repository{
		Platform:            platform,
		Owner:               owner,
		Name:                name,
		URL:                 url,
		Description:         description,
		LocalPath:           repoPath,
		IsDirty:             isDirty,
		HasUnpushed:         hasUnpushed,
		CurrentBranch:       currentBranch,
		JiraTicketID:        jiraTicketID,
		JiraTicketIDs:       jiraTicketIDs,
		JiraStatus:          jiraStatus,
		JiraSummary:         jiraSummary,
		HasActiveJiraTicket: hasActiveJiraTicket,
	}, true
}

// browseLocalRepos finds local repositories and lets user select one
func browseLocalRepos(filter string, platform string, noCache bool) *Repository {
	repoChan := make(chan Repository, 100)

	go func() {
		fetchChan := make(chan Repository, 100)
		go func() {
			findLocalRepos(filter, noCache, fetchChan)
			close(fetchChan)
		}()

		for repo := range fetchChan {
			if platform == "" || repo.Platform == platform {
				repoChan <- repo
			}
		}
		close(repoChan)
	}()

	return selectRepoWithFzf(repoChan)
}
