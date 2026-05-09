package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

// fetchGitLabAllPages fetches all pages from GitLab API and returns repos
func fetchGitLabAllPages(token string) []Repository {
	return fetchAllPages(4, 100, func(page int) []Repository {
		return fetchGitLabPage(page, token)
	})
}

func fetchGitLab(ch chan<- Repository, noCache bool, backgroundRefresh bool, cacheWg *sync.WaitGroup) {
	token := getGitLabToken()
	if token == "" {
		return
	}

	var cachedRepos []Repository

	if !noCache {
		cachedRepos = loadReposFromDB("gitlab")
	}

	if len(cachedRepos) > 0 {
		for _, repo := range cachedRepos {
			ch <- repo
		}

		if backgroundRefresh && isBatchStale("gitlab") {
			cacheWg.Add(1)
			go func() {
				defer cacheWg.Done()
				freshRepos := fetchGitLabAllPages(token)
				if len(freshRepos) > 0 {
					if err := saveReposToDB("gitlab", freshRepos); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
					}
				}
			}()
		}
		return
	}

	freshRepos := fetchGitLabAllPages(token)

	for _, repo := range freshRepos {
		ch <- repo
	}

	if len(freshRepos) > 0 {
		if err := saveReposToDB("gitlab", freshRepos); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
		}
	}
}

func gitlabAPIBase() string {
	return fmt.Sprintf("https://%s/api/v4", getSettings().GitLabHost)
}

func fetchGitLabPage(page int, token string) []Repository {
	apiURL := fmt.Sprintf("%s/projects?membership=true&archived=false&per_page=100&page=%d", gitlabAPIBase(), page)

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}

	var repos []struct {
		Name              string  `json:"name"`
		PathWithNamespace string  `json:"path_with_namespace"`
		Description       *string `json:"description"`
		SSHURL            string  `json:"ssh_url_to_repo"`
		HTTPURL           string  `json:"http_url_to_repo"`
		Stars             int     `json:"star_count"`
	}

	json.NewDecoder(resp.Body).Decode(&repos)
	resp.Body.Close()

	var result []Repository
	for _, r := range repos {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}

		parts := strings.Split(r.PathWithNamespace, "/")
		repoName := parts[len(parts)-1]
		ownerPath := strings.Join(parts[:len(parts)-1], "/")

		result = append(result, Repository{
			Platform:    "gitlab",
			Owner:       ownerPath,
			Name:        repoName,
			URL:         r.SSHURL,
			HTTPSURL:    r.HTTPURL,
			Language:    "Unknown",
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return result
}

func searchGitLab(query string, ch chan<- Repository) {
	token := getGitLabToken()
	if token == "" {
		return
	}
	repos := fetchAllPages(4, 100, func(page int) []Repository {
		return searchGitLabPage(query, page, token)
	})
	for _, r := range repos {
		ch <- r
	}
}

func searchGitLabPage(query string, page int, token string) []Repository {
	apiURL := fmt.Sprintf("%s/projects?membership=true&archived=false&search=%s&per_page=100&page=%d",
		gitlabAPIBase(), url.QueryEscape(query), page)

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}

	var repos []struct {
		Name              string  `json:"name"`
		PathWithNamespace string  `json:"path_with_namespace"`
		Description       *string `json:"description"`
		SSHURL            string  `json:"ssh_url_to_repo"`
		HTTPURL           string  `json:"http_url_to_repo"`
		Stars             int     `json:"star_count"`
	}

	json.NewDecoder(resp.Body).Decode(&repos)
	resp.Body.Close()

	var result []Repository
	for _, r := range repos {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}

		parts := strings.Split(r.PathWithNamespace, "/")
		repoName := parts[len(parts)-1]
		ownerPath := strings.Join(parts[:len(parts)-1], "/")

		result = append(result, Repository{
			Platform:    "gitlab",
			Owner:       ownerPath,
			Name:        repoName,
			URL:         r.SSHURL,
			HTTPSURL:    r.HTTPURL,
			Language:    "Unknown",
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return result
}
