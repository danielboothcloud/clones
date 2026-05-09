package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
)

func main() {
	args := parseArgs()

	for _, cmd := range []string{"fzf", "git"} {
		if _, err := exec.LookPath(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "✗ Missing %s. Install with: brew install %s\n", cmd, cmd)
			os.Exit(1)
		}
	}

	if args.LocalMode {
		selectedRepo := browseLocalRepos(args.Filter, args.Platform)
		if selectedRepo == nil {
			os.Exit(0)
		}

		performLocalOperation(selectedRepo)
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

	// Fetch local repos FIRST (blocking) so they appear before remote repos
	if fetchLocal {
		findLocalRepos(args.Filter, fetchChan)
	}

	if shouldFetchGitHub {
		wg.Add(1)
		if args.Filter != "" {
			go func() {
				defer wg.Done()
				searchGitHub(args.Filter, fetchChan)
			}()
		} else {
			go func() {
				defer wg.Done()
				fetchGitHub(fetchChan, args.NoCache, true, &cacheWg)
			}()
		}
	}

	if shouldFetchGitLab {
		wg.Add(1)
		if args.Filter != "" {
			go func() {
				defer wg.Done()
				searchGitLab(args.Filter, fetchChan)
			}()
		} else {
			go func() {
				defer wg.Done()
				fetchGitLab(fetchChan, args.NoCache, true, &cacheWg)
			}()
		}
	}

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

	go func() {
		wg.Wait()
		close(fetchChan)
	}()

	selectedRepo := selectRepoWithFzf(repoChan)
	if selectedRepo == nil {
		cacheWg.Wait()
		os.Exit(0)
	}

	if selectedRepo.LocalPath != "" {
		performLocalOperation(selectedRepo)
		return
	}

	defaultBranch := getDefaultBranch(selectedRepo)
	selectedBranch := selectBranchWithFzf(selectedRepo, defaultBranch)

	targetDir := cloneOrUpdate(selectedRepo, selectedBranch)

	cacheWg.Wait()

	fmt.Println(targetDir)
}
