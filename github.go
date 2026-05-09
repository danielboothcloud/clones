package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
)

// githubAPIBase returns the REST API base URL for the configured host.
// Public github.com uses api.github.com; GitHub Enterprise Server uses
// https://<host>/api/v3 per GHES API conventions.
func githubAPIBase() string {
	host := getSettings().GitHubHost
	if host == "" || host == "github.com" {
		return "https://api.github.com"
	}
	return "https://" + host + "/api/v3"
}

// fetchGitHubAllPages fetches all pages from GitHub API and returns repos
func fetchGitHubAllPages(token string) []Repository {
	return fetchAllPages(4, 100, func(page int) []Repository {
		return fetchGitHubPage(page, token)
	})
}

func fetchGitHub(ch chan<- Repository, noCache bool, backgroundRefresh bool, cacheWg *sync.WaitGroup) {
	token := getGitHubToken()
	if token == "" {
		return
	}

	var cachedRepos []Repository

	if !noCache {
		cachedRepos = loadReposFromDB("github")
	}

	if len(cachedRepos) > 0 {
		for _, repo := range cachedRepos {
			ch <- repo
		}

		if backgroundRefresh && isBatchStale("github") {
			cacheWg.Add(1)
			go func() {
				defer cacheWg.Done()
				freshRepos := fetchGitHubAllPages(token)
				if len(freshRepos) > 0 {
					if err := saveReposToDB("github", freshRepos); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
					}
				}
			}()
		}
		return
	}

	freshRepos := fetchGitHubAllPages(token)

	for _, repo := range freshRepos {
		ch <- repo
	}

	if len(freshRepos) > 0 {
		if err := saveReposToDB("github", freshRepos); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
		}
	}
}

func fetchGitHubPage(page int, token string) []Repository {
	url := fmt.Sprintf("%s/user/repos?per_page=100&page=%d&affiliation=owner,collaborator,organization_member", githubAPIBase(), page)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil
	}

	var repos []struct {
		Name        string                 `json:"name"`
		Owner       struct{ Login string } `json:"owner"`
		Description *string                `json:"description"`
		SSHURL      string                 `json:"ssh_url"`
		CloneURL    string                 `json:"clone_url"`
		Language    *struct{ Name string } `json:"language"`
		Stars       int                    `json:"stargazers_count"`
	}

	_ = json.NewDecoder(resp.Body).Decode(&repos)
	_ = resp.Body.Close()

	var result []Repository
	for _, r := range repos {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}
		lang := "Unknown"
		if r.Language != nil {
			lang = r.Language.Name
		}

		result = append(result, Repository{
			Platform:    "github",
			Owner:       r.Owner.Login,
			Name:        r.Name,
			URL:         r.SSHURL,
			HTTPSURL:    r.CloneURL,
			Language:    lang,
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return result
}

func searchGitHub(query string, ch chan<- Repository) {
	token := getGitHubToken()
	if token == "" {
		return
	}
	repos := fetchAllPages(4, 100, func(page int) []Repository {
		return searchGitHubPage(query, page, token)
	})
	for _, r := range repos {
		ch <- r
	}
}

func searchGitHubPage(query string, page int, token string) []Repository {
	q := url.QueryEscape(query + " user:@me")
	apiURL := fmt.Sprintf("%s/search/repositories?q=%s&per_page=100&page=%d", githubAPIBase(), q, page)

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil
	}

	var result struct {
		Items []struct {
			Name        string                 `json:"name"`
			Owner       struct{ Login string } `json:"owner"`
			Description *string                `json:"description"`
			SSHURL      string                 `json:"ssh_url"`
			CloneURL    string                 `json:"clone_url"`
			Language    *string                `json:"language"`
			Stars       int                    `json:"stargazers_count"`
		} `json:"items"`
	}

	_ = json.NewDecoder(resp.Body).Decode(&result)
	_ = resp.Body.Close()

	var repos []Repository
	for _, r := range result.Items {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}
		lang := "Unknown"
		if r.Language != nil {
			lang = *r.Language
		}

		repos = append(repos, Repository{
			Platform:    "github",
			Owner:       r.Owner.Login,
			Name:        r.Name,
			URL:         r.SSHURL,
			HTTPSURL:    r.CloneURL,
			Language:    lang,
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return repos
}
