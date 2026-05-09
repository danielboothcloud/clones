package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Jira ticket pattern: PROJECT-123 (case insensitive: letters, hyphen, numbers)
var jiraTicketRegex = regexp.MustCompile(`(?i)[a-z]+-\d+`)

// extractJiraTicketID extracts Jira ticket ID from branch name.
// Supports formats: "PROJ-123-feature", "feature/PROJ-123", "PROJ-123".
func extractJiraTicketID(branch string) string {
	branch = strings.TrimPrefix(branch, "feature/")
	branch = strings.TrimPrefix(branch, "bugfix/")
	branch = strings.TrimPrefix(branch, "hotfix/")
	branch = strings.TrimPrefix(branch, "release/")

	parts := strings.Split(branch, "/")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if jiraTicketRegex.MatchString(part) {
			return part
		}
		if matches := jiraTicketRegex.FindString(part); matches != "" {
			return matches
		}
	}

	return ""
}

// Jira ticket cache to avoid redundant API calls
var (
	jiraCache   = make(map[string]*JiraTicket)
	jiraCacheMu sync.RWMutex
)

// fetchJiraTicket fetches ticket information from Jira API with caching
func fetchJiraTicket(ticketID string) *JiraTicket {
	jiraCacheMu.RLock()
	if cached, exists := jiraCache[ticketID]; exists {
		jiraCacheMu.RUnlock()
		return cached
	}
	jiraCacheMu.RUnlock()

	token, baseURL, email := getJiraConfig()
	if token == "" || baseURL == "" {
		return nil
	}

	apiURL := fmt.Sprintf("%s/rest/api/3/issue/%s",
		strings.TrimSuffix(baseURL, "/"), ticketID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil
	}

	req.SetBasicAuth(email, token)
	req.Header.Set("Accept", "application/json")

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var ticket JiraTicket
	if err := json.NewDecoder(resp.Body).Decode(&ticket); err != nil {
		return nil
	}

	jiraCacheMu.Lock()
	jiraCache[ticketID] = &ticket
	jiraCacheMu.Unlock()

	return &ticket
}

// isActiveJiraStatus checks if a Jira status is considered "active"
func isActiveJiraStatus(status string) bool {
	activeStatuses := map[string]bool{
		"In Progress": true,
		"In Review":   true,
		"To Do":       true,
		"Pending":     true,
	}
	return activeStatuses[status]
}

// JiraJQLResult is the cached result of a JQL search.
//   - Tickets maps ticket ID → full ticket (key, summary, status). Empty when JQL was not configured
//     or the request failed; use the OK flag to distinguish.
//   - OK is true only when the API call returned successfully. This is what callers should use to
//     decide between "filter to JQL set" vs "no filter / API failure → don't filter at all".
type JiraJQLResult struct {
	Tickets map[string]*JiraTicket
	OK      bool
}

var (
	jiraJQLCache    = make(map[string]JiraJQLResult)
	jiraJQLCacheMu  sync.RWMutex
	jiraJQLCacheAt  = make(map[string]time.Time)
	jiraJQLCacheTTL = 15 * time.Minute
)

// loadJiraTicketsByJQL searches for tickets using JQL and returns the full ticket data
// (summary + status), so callers don't need a follow-up per-ticket fetch.
// Results are cached for 15 minutes.
//
// Returns OK=false (and an empty map) when JQL is empty, when Jira config is missing,
// or when the API call fails. Callers should branch on OK rather than len(Tickets).
func loadJiraTicketsByJQL(jql string) JiraJQLResult {
	if jql == "" {
		return JiraJQLResult{}
	}

	jiraJQLCacheMu.RLock()
	if cached, exists := jiraJQLCache[jql]; exists {
		if at, ok := jiraJQLCacheAt[jql]; ok && time.Since(at) < jiraJQLCacheTTL {
			jiraJQLCacheMu.RUnlock()
			return cached
		}
	}
	jiraJQLCacheMu.RUnlock()

	token, baseURL, email := getJiraConfig()
	if token == "" || baseURL == "" {
		return JiraJQLResult{}
	}

	apiURL := fmt.Sprintf("%s/rest/api/3/search/jql?jql=%s&fields=summary,status&maxResults=1000",
		strings.TrimSuffix(baseURL, "/"),
		url.QueryEscape(jql))

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return JiraJQLResult{}
	}

	req.SetBasicAuth(email, token)
	req.Header.Set("Accept", "application/json")

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return JiraJQLResult{}
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Issues []JiraTicket `json:"issues"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return JiraJQLResult{}
	}

	tickets := make(map[string]*JiraTicket, len(result.Issues))
	for i := range result.Issues {
		t := result.Issues[i]
		tickets[t.Key] = &t
	}

	out := JiraJQLResult{Tickets: tickets, OK: true}

	jiraJQLCacheMu.Lock()
	jiraJQLCache[jql] = out
	jiraJQLCacheAt[jql] = time.Now()
	jiraJQLCacheMu.Unlock()

	return out
}
