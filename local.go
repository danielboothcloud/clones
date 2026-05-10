package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// findLocalRepos walks the configured clone root looking for git repositories
func findLocalRepos(filter string, ch chan<- Repository) {
	jiraConfig, err := loadJiraConfig()
	if err != nil {
		jiraConfig = &JiraConfig{}
	}

	// Single JQL call returns key+summary+status for every matching ticket — avoids one
	// extra HTTP call per repo. When JQL is unconfigured, jql.OK is false and we fall back
	// to per-ticket fetchJiraTicket below.
	var jql JiraJQLResult
	if jiraConfig.Enabled && jiraConfig.JQL != "" {
		jql = loadJiraTicketsByJQL(jiraConfig.JQL)
	}

	workDir := getSettings().CloneRoot

	if _, err := os.Stat(workDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "✗ Directory does not exist: %s\n", workDir)
		return
	}

	// Phase 1: walk the tree to collect repo paths only — no git subprocesses yet.
	var repoPaths []string
	err = filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && info.Name() == ".git" {
			repoPaths = append(repoPaths, filepath.Dir(path))
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error walking directory: %v\n", err)
	}

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
				if matchesFilter(&repo, filter) {
					ch <- repo
				}
			}
		}()
	}
	wg.Wait()
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
func browseLocalRepos(filter string, platform string) *Repository {
	repoChan := make(chan Repository, 100)

	go func() {
		fetchChan := make(chan Repository, 100)
		go func() {
			findLocalRepos(filter, fetchChan)
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
