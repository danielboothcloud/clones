package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTP client singleton for connection pooling
var (
	sharedHTTPClient *http.Client
	clientOnce       sync.Once
)

func getHTTPClient() *http.Client {
	clientOnce.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}
		sharedHTTPClient = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	})
	return sharedHTTPClient
}

// doRequest sends req and retries on 429 / 5xx responses with exponential backoff.
// Honors the Retry-After header on 429s when present. Caller owns the returned response body.
//
// To preserve existing call-site semantics, doRequest does not wrap timeouts or DNS errors in
// a retry loop — those still surface as the underlying err from Do.
func doRequest(req *http.Request) (*http.Response, error) {
	const maxAttempts = 4
	backoff := 500 * time.Millisecond

	for attempt := 1; ; attempt++ {
		resp, err := getHTTPClient().Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return resp, nil
		}
		if attempt == maxAttempts {
			return resp, nil
		}

		wait := backoff
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, perr := strconv.Atoi(ra); perr == nil && secs > 0 && secs <= 60 {
				wait = time.Duration(secs) * time.Second
			}
		}
		resp.Body.Close()
		time.Sleep(wait)
		backoff *= 2
	}
}

// Token caching
var (
	githubToken     string
	gitlabToken     string
	jiraToken       string
	jiraBaseURL     string
	githubTokenOnce sync.Once
	gitlabTokenOnce sync.Once
	jiraConfigOnce  sync.Once
)

func getGitHubToken() string {
	githubTokenOnce.Do(func() {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GITHUB_ACCESS_TOKEN")
		}
		if token == "" {
			homeDir, _ := os.UserHomeDir()
			data, err := os.ReadFile(filepath.Join(homeDir, ".config", "gh", "hosts.yml"))
			if err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "oauth_token:") {
						token = strings.TrimSpace(strings.TrimPrefix(line, "oauth_token:"))
						break
					}
				}
			}
		}
		githubToken = token
	})
	return githubToken
}

func getGitLabToken() string {
	gitlabTokenOnce.Do(func() {
		token := os.Getenv("GITLAB_TOKEN")
		if token == "" {
			token = os.Getenv("GITLAB_ACCESS_TOKEN")
		}
		if token == "" {
			homeDir, _ := os.UserHomeDir()
			data, err := os.ReadFile(filepath.Join(homeDir, ".config", "glab-cli", "config.yml"))
			if err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "token:") {
						token = strings.TrimSpace(strings.TrimPrefix(line, "token:"))
						break
					}
				}
			}
		}
		gitlabToken = token
	})
	return gitlabToken
}

// getJiraConfig loads Jira configuration from environment variables or config file
func getJiraConfig() (token, baseURL, email string) {
	jiraConfigOnce.Do(func() {
		jiraToken = os.Getenv("JIRA_API_TOKEN")
		jiraBaseURL = os.Getenv("JIRA_BASE_URL")

		config, _ := loadJiraConfig()
		if config != nil {
			if jiraToken == "" && config.Token != "" {
				jiraToken = config.Token
			}
			if jiraBaseURL == "" && config.BaseURL != "" {
				jiraBaseURL = config.BaseURL
			}
			email = config.Email
		}
	})
	return jiraToken, jiraBaseURL, email
}
