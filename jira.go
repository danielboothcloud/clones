package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nutsdb/nutsdb"
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
	// In-process L1 for JQL results, keyed by the composite DB cache key
	// (email|baseURL|jql) so different instances/identities never cross-pollute.
	jiraJQLCache   = make(map[string]JiraJQLResult)
	jiraJQLCacheMu sync.RWMutex
	jiraJQLCacheAt = make(map[string]time.Time)

	// jiraJQLCacheTTL is how long a JQL result stays fresh — one hour, both in
	// process memory (L1) and in NutsDB (L2). Jira labels in listings can
	// therefore lag reality by up to an hour; --no-cache goes live.
	jiraJQLCacheTTL = time.Hour
)

// loadJiraTicketsByJQL searches for tickets using JQL and returns the full ticket data
// (summary + status), so callers don't need a follow-up per-ticket fetch.
// Lookup chain: in-process cache (L1) → NutsDB (L2) → live API; successful
// fetches write both layers. noCache skips both layers (and re-fetches live)
// so `clones --no-cache` means fresh data everywhere.
//
// Returns OK=false (and an empty map) when JQL is empty, when Jira config is missing,
// or when the API call fails. Callers should branch on OK rather than len(Tickets).
func loadJiraTicketsByJQL(jql string, noCache bool) JiraJQLResult {
	if jql == "" {
		return JiraJQLResult{}
	}

	token, baseURL, email := getJiraConfig()
	if token == "" || baseURL == "" {
		return JiraJQLResult{}
	}
	cacheKey := jiraJQLCacheKey(email, baseURL, jql)

	if !noCache {
		jiraJQLCacheMu.RLock()
		if cached, exists := jiraJQLCache[cacheKey]; exists {
			if at, ok := jiraJQLCacheAt[cacheKey]; ok && time.Since(at) < jiraJQLCacheTTL {
				jiraJQLCacheMu.RUnlock()
				return cached
			}
		}
		jiraJQLCacheMu.RUnlock()

		// L2: served from NutsDB so every fresh clones process skips the
		// Atlassian round trip within the TTL window.
		if cached, ok := loadJiraJQLFromDB(cacheKey); ok {
			jiraJQLCacheMu.Lock()
			jiraJQLCache[cacheKey] = cached
			jiraJQLCacheAt[cacheKey] = time.Now()
			jiraJQLCacheMu.Unlock()
			return cached
		}
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

	// Write-through both layers. Persistence failure is non-fatal: listing
	// works, next run re-fetches.
	jiraJQLCacheMu.Lock()
	jiraJQLCache[cacheKey] = out
	jiraJQLCacheAt[cacheKey] = time.Now()
	jiraJQLCacheMu.Unlock()
	if err := saveJiraJQLToDB(cacheKey, out); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not persist Jira JQL cache: %v\n", err)
	}

	return out
}

// jiraJQLCacheKey composes the cross-layer JQL cache key from the authenticated
// identity (email), the instance (baseURL), and the query. The API token is
// deliberately excluded — results are keyed to identity, not credential, so
// rotating a token does not blank the cache. Hashed so config values never
// appear in the on-disk key.
func jiraJQLCacheKey(email, baseURL, jql string) string {
	data, _ := json.Marshal(struct {
		Email   string
		BaseURL string
		JQL     string
	}{email, baseURL, jql})
	return "jql:" + fmt.Sprintf("%x", sha256.Sum256(data))
}

// jiraJQLDBSnapshot is the persisted form of a JQL result (bucketMeta).
type jiraJQLDBSnapshot struct {
	SavedAt time.Time              `json:"saved_at"`
	Tickets map[string]*JiraTicket `json:"tickets"`
}

// loadJiraJQLFromDB returns the persisted result for cacheKey when it exists
// and is younger than jiraJQLCacheTTL. Any storage problem is a miss — the
// caller falls back to the live API, which is always safe.
func loadJiraJQLFromDB(cacheKey string) (JiraJQLResult, bool) {
	db, err := getCacheDB()
	if err != nil {
		return JiraJQLResult{}, false
	}
	tx, err := db.Begin(false)
	if err != nil {
		return JiraJQLResult{}, false
	}
	defer func() { _ = tx.Rollback() }()

	value, err := tx.Get(bucketMeta, []byte(cacheKey))
	if err != nil {
		return JiraJQLResult{}, false
	}

	var snapshot jiraJQLDBSnapshot
	if err := json.Unmarshal(value, &snapshot); err != nil {
		return JiraJQLResult{}, false
	}
	if snapshot.SavedAt.IsZero() || time.Since(snapshot.SavedAt) >= jiraJQLCacheTTL {
		return JiraJQLResult{}, false
	}
	if snapshot.Tickets == nil {
		snapshot.Tickets = map[string]*JiraTicket{}
	}
	return JiraJQLResult{Tickets: snapshot.Tickets, OK: true}, true
}

// saveJiraJQLToDB persists a successful JQL result under bucketMeta.
func saveJiraJQLToDB(cacheKey string, result JiraJQLResult) error {
	value, err := json.Marshal(jiraJQLDBSnapshot{SavedAt: time.Now(), Tickets: result.Tickets})
	if err != nil {
		return err
	}
	db, err := getCacheDB()
	if err != nil {
		return err
	}
	tx, err := db.Begin(true)
	if err != nil {
		return err
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketMeta); err != nil && !isBucketExistsErr(err) {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Put(bucketMeta, []byte(cacheKey), value, 0); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
