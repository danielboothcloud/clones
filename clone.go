package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func getDefaultBranch(repo *Repository) string {
	var token, url string

	if repo.Platform == "github" {
		token = getGitHubToken()
		url = fmt.Sprintf("%s/repos/%s/%s", githubAPIBase(), repo.Owner, repo.Name)
	} else {
		token = getGitLabToken()
		projectPath := strings.ReplaceAll(repo.Owner+"/"+repo.Name, "/", "%2F")
		url = fmt.Sprintf("https://%s/api/v4/projects/%s", getSettings().GitLabHost, projectPath)
	}

	if token == "" {
		return "main"
	}

	req, _ := http.NewRequest("GET", url, nil)
	if repo.Platform == "github" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
	} else {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return "main"
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		DefaultBranch string `json:"default_branch"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if result.DefaultBranch == "" {
		return "main"
	}
	return result.DefaultBranch
}

// cloneOrUpdate ensures the repo exists at targetDir on the configured branch and is
// up to date. New clones use `git clone -b`; existing clones get a checkout + pull.
//
// All git work runs through runGitInRepo / runClone, which honor the "clone" entry in
// remote.ops — when configured, the heavy FS-touching git operations execute on the
// remote host (avoiding fuse-t / NFS unlink issues during pack churn).
//
// Returns the local target dir regardless of where the work happened — the shell wrapper
// always cd's into the local view.
func cloneOrUpdate(repo *Repository, branch string) string {
	targetDir := filepath.Join(getSettings().CloneRoot, repo.Owner, repo.Name)

	if _, err := os.Stat(targetDir); err == nil {
		if _, err := os.Stat(filepath.Join(targetDir, ".git")); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "✗ Directory exists but is not a git repository")
			os.Exit(1)
		}

		// Read current branch locally — fuse-t handles small reads fine, no need to
		// pay an SSH round-trip for one ref lookup.
		currentBranch := getCurrentBranch(targetDir)

		if currentBranch != branch {
			// Try existing local branch first; fall back to creating a tracking branch.
			if err := runGitInRepo("clone", targetDir, "checkout", branch); err != nil {
				_ = runGitInRepo("clone", targetDir, "checkout", "-t", "origin/"+branch)
			}
		}

		_ = runGitInRepo("clone", targetDir, "pull")
		return targetDir
	}

	if err := runClone("clone", targetDir, branch, cloneURL(repo)); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to clone: %v\n", err)
		os.Exit(1)
	}

	if shouldRunRemote("clone") && !waitForRemoteSync(targetDir) {
		fmt.Fprintf(os.Stderr, "⚠ Cloned remotely but local mount hasn't synced yet — try `cd %s` manually.\n", targetDir)
	}

	return targetDir
}

// waitForRemoteSync forces fuse-t (or similar) to refresh its parent-dir cache
// so a path just created on the remote becomes visible locally. Re-reading the
// parent invalidates fuse's stat cache; we then poll until the child appears or
// remote.sync_timeout_seconds elapses.
func waitForRemoteSync(targetDir string) bool {
	parent := filepath.Dir(targetDir)
	timeout := 5 * time.Second
	if r := getSettings().Remote; r != nil && r.SyncTimeoutSeconds > 0 {
		timeout = time.Duration(r.SyncTimeoutSeconds) * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, _ = os.ReadDir(parent)
		if _, err := os.Stat(targetDir); err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
