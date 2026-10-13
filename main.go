package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

//go:embed VERSION
var versionFile string

// appVersion is the trimmed contents of the VERSION file, embedded into the
// binary at build time — an installed copy reports the version it was built
// from, not whatever the file says later.
var appVersion = strings.TrimSpace(versionFile)

func main() {
	args := parseArgs()

	// Handle --version before the fzf/git availability checks so it works on any machine.
	if args.Version {
		fmt.Printf("clones version %s\n", appVersion)
		return
	}

	for _, cmd := range []string{"fzf", "git"} {
		if _, err := exec.LookPath(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "✗ Missing %s. Install with: brew install %s\n", cmd, cmd)
			os.Exit(1)
		}
	}

	if args.LocalMode {
		selectedRepo := browseLocalRepos(args.Filter, args.Platform, args.NoCache)
		if selectedRepo == nil {
			waitForLocalRefresh()
			os.Exit(0)
		}

		performLocalOperation(selectedRepo)
		// Mutating ops invalidate the snapshot and void any in-flight refresh
		// (epoch guard + abandon flag) — the wait returns instantly for those.
		// Read-only ops wait so a background refresh persists for the next run.
		waitForLocalRefresh()
		return
	}

	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		config = &Config{ExcludePatterns: []string{}}
	}

	fetchChan := make(chan Repository, 500)
	var wg sync.WaitGroup
	var cacheWg sync.WaitGroup

	fetchRemote := !args.LocalMode
	fetchLocal := !args.RemoteOnly

	shouldFetchGitHub := fetchRemote && (args.Platform == "" || args.Platform == "github")
	shouldFetchGitLab := fetchRemote && (args.Platform == "" || args.Platform == "gitlab")

	if shouldFetchGitHub {
		wg.Add(1)
	}
	if shouldFetchGitLab {
		wg.Add(1)
	}

	go func() {
		defer close(fetchChan)
		// Local repos still precede remote repos, but the consumer can drain the
		// channel immediately (including snapshots larger than its buffer).
		if fetchLocal {
			findLocalRepos(args.Filter, args.NoCache, fetchChan)
		}

		if shouldFetchGitHub {
			go func() {
				defer wg.Done()
				if args.Filter != "" {
					searchGitHub(args.Filter, fetchChan)
				} else {
					fetchGitHub(fetchChan, args.NoCache, true, &cacheWg)
				}
			}()
		}

		if shouldFetchGitLab {
			go func() {
				defer wg.Done()
				if args.Filter != "" {
					searchGitLab(args.Filter, fetchChan)
				} else {
					fetchGitLab(fetchChan, args.NoCache, true, &cacheWg)
				}
			}()
		}
		wg.Wait()
	}()

	// Deduplicate (local beats remote on same owner/name) and stream to fzf in real-time
	repoChan := make(chan Repository, 500)

	go func() {
		defer close(repoChan)

		seen := make(map[string]*Repository)
		var mu sync.Mutex

		for repo := range fetchChan {
			if args.Platform != "" && repo.Platform != args.Platform {
				continue
			}

			if args.JiraFilter && !repo.HasActiveJiraTicket {
				continue
			}

			if shouldExcludeRepo(repo, config) {
				continue
			}

			key := repo.Owner + "/" + repo.Name

			mu.Lock()
			existing, exists := seen[key]

			if !exists {
				seen[key] = &repo
				mu.Unlock()
				repoChan <- repo
			} else {
				if repo.LocalPath != "" && existing.LocalPath == "" {
					seen[key] = &repo
					mu.Unlock()
					repoChan <- repo
				} else {
					mu.Unlock()
				}
			}
		}
	}()

	selectedRepo := selectRepoWithFzf(repoChan)
	if selectedRepo == nil {
		waitForLocalRefresh()
		cacheWg.Wait()
		os.Exit(0)
	}

	if selectedRepo.LocalPath != "" {
		performLocalOperation(selectedRepo)
		waitForLocalRefresh()
		return
	}

	defaultBranch := getDefaultBranch(selectedRepo)
	selectedBranch := selectBranchWithFzf(selectedRepo, defaultBranch)

	targetDir := cloneOrUpdate(selectedRepo, selectedBranch)

	waitForLocalRefresh()
	cacheWg.Wait()

	fmt.Println(targetDir)
}
